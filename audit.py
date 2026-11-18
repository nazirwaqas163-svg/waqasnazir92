from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_TIMEOUT = float(os.getenv("SUPABASE_TIMEOUT", "10"))

logger = logging.getLogger(__name__)

# SHA-256 hex digest of empty input — genesis predecessor for the first event.
GENESIS_HASH = hashlib.sha256(b"").hexdigest()
AI_EVENT_HASH_FIELDS = (
    "event_id", "timestamp", "agent_id", "action", "input_text", "output_text",
    "bdi_score", "status", "session_id", "parent_session_id", "entropy", "org_id",
)


def _canonical_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(event_data: Dict[str, Any], previous_hash: str) -> str:
    material = {"data": event_data, "previous_hash": previous_hash}
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def verify_ai_event_row(row: Dict[str, Any]) -> bool:
    """Verify a persisted ai_events row against its stored payload and predecessor."""
    previous_hash = row.get("prev_hash")
    row_hash = row.get("row_hash")
    if not isinstance(previous_hash, str) or not isinstance(row_hash, str):
        return False
    payload = {field: row.get(field) for field in AI_EVENT_HASH_FIELDS}
    return _entry_hash(payload, previous_hash) == row_hash


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
                            "org_id,prev_hash,row_hash"
                        ),
                    },
                )
                response.raise_for_status()
                data = response.json()
                for row in data:
                    if "status" in row:
                        row["policy_result"] = row["status"]
                return data
        except httpx.HTTPError:
            logger.exception("Failed to fetch session events for %s", session_id)
            return []

    async def insert_trace_spans(self, rows: List[Dict[str, Any]]) -> int:
        """Idempotently insert spans; duplicate tenant/trace/span IDs are ignored."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            headers = {**self._headers(), "prefer": "resolution=ignore-duplicates,return=representation"}
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/agent_traces",
                    headers=headers,
                    params={"on_conflict": "org_id,trace_id,span_id"},
                    json=rows,
                )
                response.raise_for_status()
                body = response.json()
                return len(body) if isinstance(body, list) else 0
        except httpx.HTTPError as exc:
            logger.exception("Failed to persist agent trace spans")
            raise RuntimeError("Trace storage is unavailable") from exc

    async def get_trace_spans(
        self, *, org_id: str, trace_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Read trace spans with tenant identity always included in the filter."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            params: Dict[str, Any] = {
                "org_id": f"eq.{org_id}",
                "select": "trace_id,span_id,parent_span_id,name,kind,started_at,ended_at,status,agent_id,resource,attributes,events,ingested_at",
                "order": "started_at.asc" if trace_id else "started_at.desc",
                "limit": str(max(1, min(limit, 200))),
            }
            if trace_id:
                params["trace_id"] = f"eq.{trace_id}"
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/agent_traces",
                    headers=self._headers(),
                    params=params,
                )
                response.raise_for_status()
                body = response.json()
                return body if isinstance(body, list) else []
        except httpx.HTTPError as exc:
            logger.exception("Failed to read agent trace spans")
            raise RuntimeError("Trace storage is unavailable") from exc

    async def get_agent_isolation(self, *, org_id: str, agent_id: str) -> Optional[Dict[str, Any]]:
        """Load one active tenant-scoped isolation record."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/agent_isolations",
                    headers=self._headers(),
                    params={
                        "org_id": f"eq.{org_id}",
                        "agent_id": f"eq.{agent_id}",
                        "released_at": "is.null",
                        "select": "org_id,agent_id,reason,hold_id,isolated_at,released_at,released_by",
                        "limit": "1",
                    },
                )
                response.raise_for_status()
                rows = response.json()
                return rows[0] if rows else None
        except httpx.HTTPError as exc:
            logger.exception("Failed to read durable agent isolation")
            raise RuntimeError("Durable agent isolation is unavailable") from exc

    async def upsert_agent_isolation(
        self, *, org_id: str, agent_id: str, reason: str, hold_id: Optional[str]
    ) -> Dict[str, Any]:
        """Persist an isolation record using the org/agent composite key."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        row = {
            "org_id": org_id,
            "agent_id": agent_id,
            "reason": reason,
            "hold_id": hold_id,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
            "released_at": None,
            "released_by": None,
        }
        try:
            headers = {**self._headers(), "prefer": "resolution=merge-duplicates,return=representation"}
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/agent_isolations",
                    headers=headers,
                    params={"on_conflict": "org_id,agent_id"},
                    json=row,
                )
                response.raise_for_status()
                rows = response.json()
                return rows[0] if rows else row
        except httpx.HTTPError as exc:
            logger.exception("Failed to persist durable agent isolation")
            raise RuntimeError("Durable agent isolation is unavailable") from exc

    async def release_agent_isolation(
        self, *, org_id: str, agent_id: str, released_by: str
    ) -> Optional[Dict[str, Any]]:
        """Release one active org/agent isolation record."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            headers = {**self._headers(), "prefer": "return=representation"}
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.patch(
                    f"{self.url}/rest/v1/agent_isolations",
                    headers=headers,
                    params={
                        "org_id": f"eq.{org_id}",
                        "agent_id": f"eq.{agent_id}",
                        "released_at": "is.null",
                    },
                    json={
                        "released_at": datetime.now(timezone.utc).isoformat(),
                        "released_by": released_by,
                    },
                )
                response.raise_for_status()
                rows = response.json()
                return rows[0] if rows else None
        except httpx.HTTPError as exc:
            logger.exception("Failed to release durable agent isolation")
            raise RuntimeError("Durable agent isolation is unavailable") from exc

    async def list_agent_isolations(
        self, *, active_only: bool = True, org_id: Optional[str] = None, limit: int = 500
    ) -> List[Dict[str, Any]]:
        """List recent isolation records, optionally scoped to one organization."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        params: Dict[str, Any] = {
            "select": "org_id,agent_id,reason,hold_id,isolated_at,released_at,released_by",
            "order": "isolated_at.desc",
            "limit": str(max(1, min(limit, 1000))),
        }
        if active_only:
            params["released_at"] = "is.null"
        if org_id is not None:
            params["org_id"] = f"eq.{org_id}"
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/agent_isolations",
                    headers=self._headers(),
                    params=params,
                )
                response.raise_for_status()
                rows = response.json()
                return rows if isinstance(rows, list) else []
        except httpx.HTTPError as exc:
            logger.exception("Failed to list durable agent isolations")
            raise RuntimeError("Durable agent isolation is unavailable") from exc

    async def record_agent_session_turn(
        self, *, org_id: str, session_id: str, agent_id: str,
        input_text: str, output_text: str, max_retries: int = 8,
    ) -> Dict[str, Any]:
        """Score and persist a session turn using optimistic versioned writes."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        from session_store import SessionState

        for _ in range(max_retries):
            row = await self.get_agent_session(org_id=org_id, session_id=session_id)
            state = SessionState.from_persisted_dict(row) if row else SessionState(
                session_id=session_id, agent_id=agent_id
            )
            state.agent_id = agent_id
            score = state.record_turn(input_text, output_text)
            saved = await self.write_agent_session(
                org_id=org_id,
                state=state.to_persisted_dict(),
                expected_version=int(row.get("version", 0)) if row else 0,
            )
            if saved:
                return {"bdi_score": round(score, 4), "turn_count": state.turn_count}
        raise RuntimeError("Concurrent session updates did not converge")

    async def get_agent_session(
        self, *, org_id: str, session_id: str
    ) -> Optional[Dict[str, Any]]:
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/agent_sessions",
                    headers=self._headers(),
                    params={
                        "org_id": f"eq.{org_id}",
                        "session_id": f"eq.{session_id}",
                        "select": "org_id,session_id,agent_id,turn_count,bdi_score,seen_risk,created_at,last_seen_at,version",
                        "limit": "1",
                    },
                )
                response.raise_for_status()
                rows = response.json()
                return rows[0] if rows else None
        except httpx.HTTPError as exc:
            logger.exception("Failed to read durable session state")
            raise RuntimeError("Durable session state is unavailable") from exc

    async def write_agent_session(
        self, *, org_id: str, state: Dict[str, Any], expected_version: int
    ) -> bool:
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        body = {
            "p_org_id": org_id,
            "p_session_id": state["session_id"],
            "p_agent_id": state["agent_id"],
            "p_expected_version": expected_version,
            "p_turn_count": state["turn_count"],
            "p_bdi_score": state["bdi_score"],
            "p_seen_risk": state["seen_risk"],
            "p_created_at": state["created_at"],
            "p_last_seen_at": state["last_seen_at"],
        }
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/rpc/pulse_write_agent_session",
                    headers=self._headers(),
                    json=body,
                )
                response.raise_for_status()
                return response.json() is True
        except httpx.HTTPError as exc:
            logger.exception("Failed to persist durable session state")
            raise RuntimeError("Durable session state is unavailable") from exc

    async def list_active_agent_sessions(
        self, *, org_id: str, agent_id: str, within_seconds: int = 300
    ) -> List[str]:
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=within_seconds)
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/agent_sessions",
                    headers=self._headers(),
                    params={
                        "org_id": f"eq.{org_id}",
                        "agent_id": f"eq.{agent_id}",
                        "last_seen_at": f"gte.{cutoff.isoformat()}",
                        "select": "session_id",
                        "limit": "1000",
                    },
                )
                response.raise_for_status()
                rows = response.json()
                return [str(row["session_id"]) for row in rows if row.get("session_id")]
        except httpx.HTTPError as exc:
            logger.exception("Failed to list durable active sessions")
            raise RuntimeError("Durable session state is unavailable") from exc

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
            params["or"] = "(org_id.is.null,org_id.eq.demo-org)"
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
    async def get_session_turns(self, session_id: Optional[str], limit: int = 200) -> List[Dict[str, Any]]:
        """Narrow per-session lookup used by /intercept: only status + entropy
        for this session's turns, newest first."""
        if not self.configured or not session_id:
            return []
        params = {
            "session_id": f"eq.{session_id}",
            "select": "status,entropy",
            "order": "created_at.desc",
            "limit": str(limit),
        }
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/ai_events",
                    headers={"apikey": self.key or "", "authorization": f"Bearer {self.key}"},
                    params=params,
                )
                return response.json() if response.status_code == 200 else []
        except httpx.HTTPError:
            logger.exception("Failed to fetch session turns")
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
                        "order": "ledger_sequence.asc",
                        "select": "ledger_sequence,id,event_id,created_at,agent_id,action,input_text,output_text,bdi_score,status,session_id,parent_session_id,entropy,org_id,prev_hash,row_hash",
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


    async def create_evaluation_dataset_version(self, **dataset: Any) -> Dict[str, Any]:
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/rpc/create_evaluation_dataset_version",
                    headers=self._headers(),
                    json={f"p_{key}": value for key, value in dataset.items()},
                )
                response.raise_for_status()
                data = response.json()
                return data[0] if isinstance(data, list) and data else data
        except Exception as exc:
            raise RuntimeError("Could not create evaluation dataset version") from exc

    async def list_evaluation_datasets(self, org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/evaluation_datasets",
                    headers=self._headers(),
                    params={"org_id": f"eq.{org_id}", "order": "created_at.desc",
                            "select": "*", "limit": str(limit)},
                )
                response.raise_for_status()
                return response.json()
        except Exception as exc:
            raise RuntimeError("Could not list evaluation datasets") from exc

    async def get_evaluation_dataset(
        self, *, org_id: str, dataset_id: str, dataset_version: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        params: Dict[str, str] = {"org_id": f"eq.{org_id}", "dataset_id": f"eq.{dataset_id}",
                                  "select": "*", "limit": "1"}
        if dataset_version is not None:
            params["dataset_version"] = f"eq.{dataset_version}"
        else:
            params["order"] = "dataset_version.desc"
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/evaluation_datasets",
                    headers=self._headers(), params=params,
                )
                response.raise_for_status()
                rows = response.json()
                return rows[0] if rows else None
        except Exception as exc:
            raise RuntimeError("Could not fetch evaluation dataset") from exc

    async def insert_evaluation_run(self, run: Dict[str, Any]) -> Dict[str, Any]:
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/evaluation_runs",
                    headers={**self._headers(), "content-type": "application/json",
                             "prefer": "return=representation"},
                    json=run,
                )
                response.raise_for_status()
                rows = response.json()
                return rows[0] if rows else run
        except Exception as exc:
            raise RuntimeError("Could not persist evaluation run") from exc

    async def list_evaluation_runs(
        self, *, org_id: str, dataset_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        params = {"org_id": f"eq.{org_id}", "order": "created_at.desc",
                  "select": "*", "limit": str(limit)}
        if dataset_id:
            params["dataset_id"] = f"eq.{dataset_id}"
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/evaluation_runs",
                    headers=self._headers(), params=params,
                )
                response.raise_for_status()
                return response.json()
        except Exception as exc:
            raise RuntimeError("Could not list evaluation runs") from exc

    async def get_circuit_breaker_state(self) -> Dict[str, Any]:
        """Read the shared circuit-breaker state. An empty table means closed."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.get(
                    f"{self.url}/rest/v1/circuit_breaker_state",
                    headers=self._headers(),
                    params={"singleton_id": "eq.true", "select": "*", "limit": "1"},
                )
                response.raise_for_status()
                rows = response.json()
                return rows[0] if rows else {
                    "singleton_id": True, "state": "closed", "reason": "initial state",
                    "bdi_score": 0.0, "entropy": 0.0, "opened_at": None,
                }
        except Exception as exc:
            raise RuntimeError("Could not read durable circuit-breaker state") from exc

    async def set_circuit_breaker_state(
        self, *, state: str, reason: str, bdi_score: float = 0.0, entropy: float = 0.0
    ) -> Dict[str, Any]:
        """Persist the global circuit-breaker state using a singleton upsert."""
        if not self.configured:
            raise RuntimeError("Supabase is not configured")
        now = datetime.now(timezone.utc).isoformat()
        row = {
            "singleton_id": True, "state": state, "reason": reason,
            "bdi_score": float(bdi_score), "entropy": float(entropy),
            "opened_at": now if state == "open" else None, "updated_at": now,
        }
        try:
            async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
                response = await client.post(
                    f"{self.url}/rest/v1/circuit_breaker_state",
                    headers={
                        **self._headers(),
                        "content-type": "application/json",
                        "prefer": "resolution=merge-duplicates,return=representation",
                    },
                    params={"on_conflict": "singleton_id"},
                    json=row,
                )
                response.raise_for_status()
                rows = response.json()
                return rows[0] if rows else row
        except Exception as exc:
            raise RuntimeError("Could not persist durable circuit-breaker state") from exc

supabase_audit_client = SupabaseAuditClient(SUPABASE_URL, SUPABASE_KEY)


# ── Phase 12: Replay Sessions ────────────────────────────────

async def flag_session_for_replay(
    session_id: str,
    org_id: str,
    trigger_reason: str = "manual",
    flagged_by: str = "system",
) -> dict:
    if not supabase_audit_client.configured:
        return {}
    row = {
        "session_id": session_id,
        "org_id": org_id,
        "flagged_by": flagged_by,
        "trigger_reason": trigger_reason,
        "status": "pending",
        "flagged_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
            response = await client.post(
                f"{supabase_audit_client.url}/rest/v1/replay_sessions",
                headers={
                    "apikey": supabase_audit_client.key or "",
                    "authorization": f"Bearer {supabase_audit_client.key}",
                    "content-type": "application/json",
                    "prefer": "return=representation",
                },
                json=row,
            )
            if response.status_code in (200, 201):
                data = response.json()
                return data[0] if data else row
            return {}
    except Exception as e:
        logger.error(f"flag_session_for_replay error: {e}")
        return {}


async def get_replay_sessions(org_id: str, status: str = None) -> list:
    if not supabase_audit_client.configured:
        return []
    params = {
        "org_id": f"eq.{org_id}",
        "order": "flagged_at.desc",
        "limit": "100",
        "select": "*",
    }
    if status:
        params["status"] = f"eq.{status}"
    try:
        async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
            response = await client.get(
                f"{supabase_audit_client.url}/rest/v1/replay_sessions",
                headers={
                    "apikey": supabase_audit_client.key or "",
                    "authorization": f"Bearer {supabase_audit_client.key}",
                },
                params=params,
            )
            return response.json() if response.status_code == 200 else []
    except Exception as e:
        logger.error(f"get_replay_sessions error: {e}")
        return []


async def get_replay_session_events(session_id: str, org_id: str) -> list:
    if not supabase_audit_client.configured:
        return []
    try:
        async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
            response = await client.get(
                f"{supabase_audit_client.url}/rest/v1/ai_events",
                headers={
                    "apikey": supabase_audit_client.key or "",
                    "authorization": f"Bearer {supabase_audit_client.key}",
                },
                params={
                    "session_id": f"eq.{session_id}",
                    "org_id": f"eq.{org_id}",
                    "order": "timestamp.asc",
                    "select": (
                        "event_id,timestamp,agent_id,session_id,org_id,"
                        "action,bdi_score,entropy,status,jurisdiction,"
                        "input_text,output_text,metadata,prev_hash,row_hash"
                    ),
                },
            )
            return response.json() if response.status_code == 200 else []
    except Exception as e:
        logger.error(f"get_replay_session_events error: {e}")
        return []


async def mark_replay_reviewed(
    session_id: str,
    org_id: str,
    reviewed_by: str = "dashboard",
    notes: str = "",
) -> bool:
    if not supabase_audit_client.configured:
        return False
    try:
        async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
            response = await client.patch(
                f"{supabase_audit_client.url}/rest/v1/replay_sessions",
                headers={
                    "apikey": supabase_audit_client.key or "",
                    "authorization": f"Bearer {supabase_audit_client.key}",
                    "content-type": "application/json",
                },
                params={
                    "session_id": f"eq.{session_id}",
                    "org_id": f"eq.{org_id}",
                },
                json={
                    "status": "reviewed",
                    "reviewed_at": datetime.now(timezone.utc).isoformat(),
                    "reviewed_by": reviewed_by,
                    "notes": notes,
                },
            )
            return response.status_code in (200, 204)
    except Exception as e:
        logger.error(f"mark_replay_reviewed error: {e}")
        return False

