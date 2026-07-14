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
        with self._lock:
            if limit <= 0:
                return []
            return list(self._chain[-limit:])

    def log_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
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
ai_events_logger = Logger()


class SupabaseAuditClient:
    def __init__(
        self,
        url: Optional[str],
        key: Optional[str],
        chain_logger: Optional[Logger] = None,
        ai_events_chain_logger: Optional[Logger] = None,
    ) -> None:
        self.url = url.rstrip("/") if url else None
        self.key = key
        self._chain_logger = chain_logger if chain_logger is not None else audit_logger
        self._ai_events_chain_logger = (
            ai_events_chain_logger if ai_events_chain_logger is not None else ai_events_logger
        )

    @property
    def configured(self) -> bool:
        return bool(self.url and self.key)

    def _headers(self) -> Dict[str, str]:
        return {
            "apikey": self.key or "",
            "authorization": f"Bearer {self.key}",
            "content-type": "application/json",
            "prefer": "return=minimal",
        }

    async def _post_row(self, table: str, row: Dict[str, Any]) -> bool:
        if not self.configured:
            return False
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/{table}",
                    headers=self._headers(),
                    json=row,
                )
                response.raise_for_status()
            return True
        except httpx.HTTPError:
            logger.exception("Failed to insert into %s", table)
            return False

    async def insert_audit_log(
        self,
        *,
        agent_id: Optional[str],
        request_payload: Dict[str, Any],
        response_payload: Dict[str, Any],
        bdi_score: Optional[float],
        event_id: Optional[str] = None,
    ) -> str:
        event_id = event_id or str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        event_data = {
            "id": event_id,
            "created_at": created_at,
            "agent_id": agent_id,
            "request_payload": request_payload,
            "response_payload": response_payload,
            "bdi_score": bdi_score,
        }
        chain_entry = self._chain_logger.log_event(event_data)

        if not self.configured:
            logger.warning("Skipping audit log insert because Supabase is not configured")
            return event_id

        row = {
            **event_data,
            "chain_hash": chain_entry["hash"],
            "chain_previous_hash": chain_entry["previous_hash"],
        }
        await self._post_row("audit_logs", row)
        return event_id

    async def insert_ai_event(
    self,
    *,
    event_id: str,
    timestamp: str,
    agent_id: Optional[str],
    action: str,
    input_text: str,
    output_text: str,
    bdi_score: Optional[float],
    policy_result: str,
    session_id: Optional[str] = None,
    parent_session_id: Optional[str] = None,
    entropy: Optional[float] = None,
    org_id: Optional[str] = None,
) -> bool:
        chain_payload = {
            "event_id": event_id,
            "timestamp": timestamp,
            "agent_id": agent_id,
            "action": action,
            "input_text": input_text,
            "output_text": output_text,
            "bdi_score": bdi_score,
            "status": policy_result,
            "session_id": session_id,
            "parent_session_id": parent_session_id,
            "entropy": entropy,
            "org_id": org_id,
        }
        chain_entry = self._ai_events_chain_logger.log_event(chain_payload)

        if not self.configured:
            logger.warning("Skipping ai_events insert because Supabase is not configured")
            return False

        row = {
            **chain_payload,
            "prev_hash": chain_entry["previous_hash"],
            "row_hash": chain_entry["hash"],
        }
        return await self._post_row("ai_events", row)

    async def get_session_events(self, session_id: str) -> List[Dict[str, Any]]:
        if not self.configured:
            return []
        try:
            headers = {
                "apikey": self.key or "",
                "authorization": f"Bearer {self.key}",
                "content-type": "application/json",
            }
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/ai_events",
                    headers=headers,
                    params={
                        "session_id": f"eq.{session_id}",
                        "order": "timestamp.asc",
                        "select": (
                            "event_id,timestamp,agent_id,action,input_text,output_text,"
                            "bdi_score,status,session_id,parent_session_id,entropy,"
                            "prev_hash,row_hash"
                        ),
                    },
                )
                response.raise_for_status()
                data = response.json()
                for row in data:
                    if "status" in row:
                        row["policy_result"] = row.pop("status")
                return data
        except httpx.HTTPError:
            logger.exception("Failed to fetch session events for %s", session_id)
            return []

    async def register_agent(
        self,
        agent_id: str,
        name: str = "",
        owner: str = "",
        scope: list = None,
        description: str = "",
        metadata: dict = None,
    ) -> dict:
        if not self.configured:
            return {"ok": False, "reason": "supabase_not_configured"}
        row = {
            "agent_id": agent_id,
            "name": name,
            "owner": owner,
            "scope": scope or [],
            "description": description,
            "metadata": metadata or {},
        }
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/agent_registry",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                        "content-type": "application/json",
                        "prefer": "return=representation",
                    },
                    json=row,
                )
                if response.status_code in (200, 201):
                    data = response.json()
                    return {"ok": True, "agent": data[0] if data else row}
                if response.status_code == 409:
                    return {"ok": False, "reason": "agent_id_already_registered"}
                return {"ok": False, "reason": response.text}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}

    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        if not self.configured:
            return None
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/agent_registry",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                    },
                    params={"agent_id": f"eq.{agent_id}", "select": "*", "limit": "1"},
                )
                rows = response.json()
                return rows[0] if rows else None
        except Exception:
            return None

    async def list_agents(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.configured:
            return []
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/agent_registry",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                    },
                    params={"select": "*", "order": "registered_at.asc", "limit": str(limit)},
                )
                return response.json() if response.status_code == 200 else []
        except Exception:
            return []

    async def update_agent_last_seen(self, agent_id: str) -> None:
        if not self.configured:
            return
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                await client.patch(
                    f"{self.url}/rest/v1/agent_registry",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                        "content-type": "application/json",
                    },
                    params={"agent_id": f"eq.{agent_id}"},
                    json={"last_seen_at": datetime.now(timezone.utc).isoformat()},
                )
        except Exception:
            pass

    def get_chain_hash_local(self, event_id: str) -> Optional[str]:
        for entry in self._chain_logger.chain:
            data = entry.get("data") or {}
            if data.get("id") == event_id:
                return entry.get("hash")
        return None

    def get_ai_event_chain_hash_local(self, event_id: str) -> Optional[str]:
        for entry in self._ai_events_chain_logger.chain:
            data = entry.get("data") or {}
            if data.get("event_id") == event_id:
                return entry.get("hash")
        return None

    async def get_recent_events(
        self, limit: int = 500, since_iso: Optional[str] = None, org_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if not self.configured:
            return []
        params = {
            "order": "created_at.desc",
            "select": (
                "event_id,created_at,timestamp,agent_id,action,input_text,"
                "output_text,bdi_score,status,session_id,parent_session_id,"
                "entropy,prev_hash,row_hash"
            ),
            "limit": str(limit),
        }
        if since_iso:
            params["created_at"] = f"gte.{since_iso}"
        if org_id:
            params["org_id"] = f"eq.{org_id}"
        else:
            params["org_id"] = "is.null"
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/ai_events",
                    headers={"apikey": self.key or "", "authorization": f"Bearer {self.key}"},
                    params=params,
                )
                return response.json() if response.status_code == 200 else []
        except httpx.HTTPError:
            logger.exception("Failed to fetch recent events")
            return []

    async def get_ai_events_chain(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.configured:
            return []
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/ai_events",
                    headers={"apikey": self.key or "", "authorization": f"Bearer {self.key}"},
                    params={
                        "order": "created_at.asc",
                        "select": "id,event_id,created_at,agent_id,prev_hash,row_hash",
                        "limit": str(limit),
                    },
                )
                return response.json() if response.status_code == 200 else []
        except httpx.HTTPError:
            logger.exception("Failed to fetch ai_events chain")
            return []

    async def insert_legal_hold(self, hold: Dict[str, Any]) -> bool:
        if not self.configured:
            return False
        row = {
            k: hold.get(k)
            for k in (
                "id", "created_at", "trigger_type", "agent_id", "session_id",
                "event_id", "chain_hash", "framework", "jurisdiction", "reason",
                "severity", "status", "evidence",
            )
        }
        return await self._post_row("legal_holds", row)

    async def list_legal_holds(
        self, status: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        if not self.configured:
            return []
        params = {"order": "created_at.desc", "select": "*", "limit": str(limit)}
        if status:
            params["status"] = f"eq.{status.upper()}"
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/legal_holds",
                    headers={"apikey": self.key or "", "authorization": f"Bearer {self.key}"},
                    params=params,
                )
                return response.json() if response.status_code == 200 else []
        except httpx.HTTPError:
            return []

    async def release_legal_hold(self, hold_id: str, released_by: str = "system") -> bool:
        if not self.configured:
            return False
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.patch(
                    f"{self.url}/rest/v1/legal_holds",
                    headers=self._headers(),
                    params={"id": f"eq.{hold_id}"},
                    json={
                        "status": "RELEASED",
                        "released_at": datetime.now(timezone.utc).isoformat(),
                        "released_by": released_by,
                    },
                )
                return response.status_code in (200, 204)
        except httpx.HTTPError:
            return False

    async def insert_org_policy(
        self,
        *,
        org_id: str,
        policy_id: str,
        name: str,
        rules: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not self.configured:
            return {"ok": False, "reason": "supabase_not_configured"}
        row = {
            "org_id": org_id,
            "policy_id": policy_id,
            "name": name,
            "rules": rules,
            "active": True,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/org_policies",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                        "content-type": "application/json",
                        "prefer": "return=representation,resolution=merge-duplicates",
                    },
                    json=row,
                )
                if response.status_code in (200, 201):
                    data = response.json()
                    return data[0] if data else row
                return {"ok": False, "reason": response.text}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}

    async def list_org_policies(self, org_id: str) -> List[Dict[str, Any]]:
        if not self.configured:
            return []
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/org_policies",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                    },
                    params={
                        "org_id": f"eq.{org_id}",
                        "active": "eq.true",
                        "order": "created_at.asc",
                        "select": "*",
                    },
                )
                return response.json() if response.status_code == 200 else []
        except Exception:
            return []

    async def deactivate_org_policy(self, policy_id: str, org_id: str) -> bool:
        if not self.configured:
            return False
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.patch(
                    f"{self.url}/rest/v1/org_policies",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                        "content-type": "application/json",
                    },
                    params={
                        "policy_id": f"eq.{policy_id}",
                        "org_id": f"eq.{org_id}",
                    },
                    json={
                        "active": False,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
                return response.status_code in (200, 204)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Phase 7 Stage 2 — Webhook Registration Methods
    # ------------------------------------------------------------------

    async def insert_webhook_registration(
        self,
        *,
        org_id: str,
        name: str,
        url: str,
        secret: str,
        events: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Insert a new webhook registration. Returns the created row."""
        if not self.configured:
            return {"ok": False, "reason": "supabase_not_configured"}
        row = {
            "org_id": org_id,
            "name": name,
            "url": url,
            "secret": secret,
            "events": events or ["legal_hold.opened"],
            "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/webhook_registrations",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                        "content-type": "application/json",
                        "prefer": "return=representation",
                    },
                    json=row,
                )
                if response.status_code in (200, 201):
                    data = response.json()
                    return data[0] if data else row
                return {"ok": False, "reason": response.text}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}

    async def list_webhook_registrations(
        self, org_id: str, active_only: bool = True
    ) -> List[Dict[str, Any]]:
        """List webhook registrations for an org."""
        if not self.configured:
            return []
        params: Dict[str, str] = {
            "org_id": f"eq.{org_id}",
            "order": "created_at.asc",
            "select": "*",
        }
        if active_only:
            params["active"] = "eq.true"
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/webhook_registrations",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                    },
                    params=params,
                )
                return response.json() if response.status_code == 200 else []
        except Exception:
            return []

    async def deactivate_webhook_registration(
        self, webhook_id: str, org_id: str
    ) -> bool:
        """Soft-delete a webhook registration."""
        if not self.configured:
            return False
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.patch(
                    f"{self.url}/rest/v1/webhook_registrations",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                        "content-type": "application/json",
                    },
                    params={
                        "id": f"eq.{webhook_id}",
                        "org_id": f"eq.{org_id}",
                    },
                    json={
                        "active": False,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
                return response.status_code in (200, 204)
        except Exception:
            return False


    async def insert_incident_report(
        self,
        *,
        hold_id: str,
        agent_id: Optional[str],
        session_id: Optional[str],
        trigger_type: Optional[str],
        severity: Optional[str],
        json_package: Dict[str, Any],
        pdf_bytes: Optional[bytes] = None,
    ) -> Optional[str]:
        """Insert a sealed incident report. Returns the report id or None."""
        if not self.configured:
            return None
        import base64
        row: Dict[str, Any] = {
            "hold_id": hold_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "trigger_type": trigger_type,
            "severity": severity,
            "json_package": json_package,
            "sealed": True,
            "dpo_email_sent": False,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        if pdf_bytes:
            row["pdf_bytes"] = base64.b64encode(pdf_bytes).decode()
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/incident_reports",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                        "content-type": "application/json",
                        "prefer": "return=representation",
                    },
                    json=row,
                )
                if response.status_code in (200, 201):
                    data = response.json()
                    return data[0].get("id") if data else None
                logger.warning("Failed to insert incident report: %s", response.text)
                return None
        except Exception:
            logger.exception("Failed to insert incident report")
            return None

    async def get_incident_report(self, hold_id: str) -> Optional[Dict[str, Any]]:
        """Fetch the incident report for a given hold_id."""
        if not self.configured:
            return None
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/incident_reports",
                    headers={
                        "apikey": self.key or "",
                        "authorization": f"Bearer {self.key}",
                    },
                    params={
                        "hold_id": f"eq.{hold_id}",
                        "select": "*",
                        "limit": "1",
                        "order": "generated_at.desc",
                    },
                )
                rows = response.json() if response.status_code == 200 else []
                return rows[0] if rows else None
        except Exception:
            logger.exception("Failed to fetch incident report for hold %s", hold_id)
            return None


supabase_audit_client = SupabaseAuditClient(SUPABASE_URL, SUPABASE_KEY)
