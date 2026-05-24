from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_TIMEOUT = float(os.getenv("SUPABASE_TIMEOUT", "10"))

logger = logging.getLogger(__name__)

# SHA-256 hex digest of empty input — genesis predecessor for the first event.
GENESIS_HASH = hashlib.sha256(b"").hexdigest()


def _canonical_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(event_data: Dict[str, Any], previous_hash: str) -> str:
    material = {"data": event_data, "previous_hash": previous_hash}
    return hashlib.sha256(_canonical_json(material)).hexdigest()


class Logger:
    """Tamper-evident audit log using a linked SHA-256 hash chain."""

    def __init__(self) -> None:
        self._chain: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    @property
    def chain(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._chain)

    @property
    def length(self) -> int:
        with self._lock:
            return len(self._chain)

    def recent_entries(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Thread-safe snapshot of the most recent chain entries."""
        with self._lock:
            if limit <= 0:
                return []
            return list(self._chain[-limit:])

    def log_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Append an event to the chain.

        The previous event's hash is stored on the new entry, then the new
        entry's hash is computed from (event_data, previous_hash).
        """
        with self._lock:
            previous_hash = self._chain[-1]["hash"] if self._chain else GENESIS_HASH
            entry: Dict[str, Any] = {
                "data": event_data,
                "previous_hash": previous_hash,
                "hash": _entry_hash(event_data, previous_hash),
            }
            self._chain.append(entry)
            return entry

    def verify_chain(self) -> bool:
        """Return True if every link matches its predecessor's stored hash."""
        with self._lock:
            entries = list(self._chain)
        expected_previous = GENESIS_HASH
        for entry in entries:
            if entry.get("previous_hash") != expected_previous:
                return False
            data = entry.get("data")
            if not isinstance(data, dict):
                return False
            if entry.get("hash") != _entry_hash(data, expected_previous):
                return False
            expected_previous = entry["hash"]
        return True


audit_logger = Logger()


class SupabaseAuditClient:
    def __init__(
        self,
        url: Optional[str],
        key: Optional[str],
        chain_logger: Optional[Logger] = None,
    ) -> None:
        self.url = url.rstrip("/") if url else None
        self.key = key
        self._chain_logger = chain_logger if chain_logger is not None else audit_logger

    @property
    def configured(self) -> bool:
        return bool(self.url and self.key)

    async def insert_audit_log(
        self,
        *,
        agent_id: Optional[str],
        request_payload: Dict[str, Any],
        response_payload: Dict[str, Any],
        bdi_score: Optional[float],
    ) -> bool:
        event_data = {
            "id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "request_payload": request_payload,
            "response_payload": response_payload,
            "bdi_score": bdi_score,
        }
        chain_entry = self._chain_logger.log_event(event_data)

        if not self.configured:
            logger.warning("Skipping audit log insert because Supabase is not configured")
            return False

        row = {
            **event_data,
            "chain_hash": chain_entry["hash"],
            "chain_previous_hash": chain_entry["previous_hash"],
        }
        headers = {
            "apikey": self.key or "",
            "authorization": f"Bearer {self.key}",
            "content-type": "application/json",
            "prefer": "return=minimal",
        }

        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/audit_logs",
                    headers=headers,
                    json=row,
                )
                response.raise_for_status()
            return True
        except httpx.HTTPError:
            logger.exception("Failed to insert audit log")
            return False


supabase_audit_client = SupabaseAuditClient(SUPABASE_URL, SUPABASE_KEY)
