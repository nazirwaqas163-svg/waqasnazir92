"""
Legal Hold + Alert — Phase 3 Stage 6.

A legal hold pins forensic evidence the moment a governance event fires:
critical drift, agent under-reporting (shadow), a malicious swarm, or a breached
ASEAN compliance deadline (build rule: missed deadline auto-triggers a hold).

Evidence integrity is anchored to the *chained* table (audit_logs.chain_hash),
not ai_events — ai_events is the readable append-only mirror; audit_logs carries
the SHA-256 hash chain that /ledger/integrity verifies.

This manager is in-memory authoritative for the running process and is
write-through persisted to Supabase by the caller. Dedupe prevents a session in
sustained critical drift from spawning a hold every turn: one ACTIVE hold per
(scope, trigger_type).
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def evaluate_triggers(
    *,
    drift_result: Optional[Dict[str, Any]] = None,
    shadow: Optional[Dict[str, Any]] = None,
    swarm: Optional[Dict[str, Any]] = None,
    deadlines: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Return the list of triggers fired by the supplied signals."""
    triggers: List[Dict[str, Any]] = []

    if drift_result and drift_result.get("status") == "critical":
        triggers.append(
            {
                "trigger_type": "critical_drift",
                "severity": "CRITICAL",
                "reason": f"Critical behavioural drift (entropy={drift_result.get('score')})",
            }
        )

    if shadow and shadow.get("flag") == "UNDER_REPORTING":
        triggers.append(
            {
                "trigger_type": "shadow_under_report",
                "severity": "HIGH",
                "reason": (
                    "Agent under-reporting risk "
                    f"(divergence={shadow.get('divergence')}, shadow_score={shadow.get('shadow_score')})"
                ),
            }
        )

    if swarm and swarm.get("swarm_detected"):
        sev = "CRITICAL" if swarm.get("overall_status") == "critical" else "HIGH"
        triggers.append(
            {
                "trigger_type": "swarm",
                "severity": sev,
                "reason": f"Malicious swarm detected ({swarm.get('clusters_found')} cluster(s))",
            }
        )

    for d in deadlines or []:
        if d.get("breached"):
            triggers.append(
                {
                    "trigger_type": "compliance_breach",
                    "severity": "CRITICAL",
                    "reason": f"{d.get('framework')} reporting deadline breached",
                    "framework": d.get("framework"),
                    "jurisdiction": d.get("jurisdiction"),
                    "dedupe_scope": d.get("framework"),
                }
            )

    return triggers


class LegalHoldManager:
    def __init__(self) -> None:
        self._holds: Dict[str, Dict[str, Any]] = {}
        self._active_keys: set = set()
        self._lock = threading.RLock()

    @staticmethod
    def _key(scope: Optional[str], trigger_type: str) -> tuple:
        return (scope or "", trigger_type)

    def has_active(self, scope: Optional[str], trigger_type: str) -> bool:
        with self._lock:
            return self._key(scope, trigger_type) in self._active_keys

    def create(
        self,
        *,
        trigger_type: str,
        reason: str,
        severity: str = "HIGH",
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        event_id: Optional[str] = None,
        chain_hash: Optional[str] = None,
        framework: Optional[str] = None,
        jurisdiction: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        dedupe_scope: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a hold, or return None if an identical ACTIVE hold already exists."""
        scope = dedupe_scope if dedupe_scope is not None else session_id
        with self._lock:
            key = self._key(scope, trigger_type)
            if key in self._active_keys:
                return None
            hold = {
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "trigger_type": trigger_type,
                "agent_id": agent_id,
                "session_id": session_id,
                "event_id": event_id,
                "chain_hash": chain_hash,
                "framework": framework,
                "jurisdiction": jurisdiction,
                "reason": reason,
                "severity": severity,
                "status": "ACTIVE",
                "evidence": evidence or {},
                "released_at": None,
                "released_by": None,
            }
            self._holds[hold["id"]] = hold
            self._active_keys.add(key)
            return hold

    def list(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            holds = list(self._holds.values())
        if status:
            holds = [h for h in holds if h["status"] == status.upper()]
        holds.sort(key=lambda h: h["created_at"], reverse=True)
        return holds[:limit]

    def get(self, hold_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._holds.get(hold_id)

    def release(self, hold_id: str, released_by: str = "system") -> Optional[Dict[str, Any]]:
        with self._lock:
            hold = self._holds.get(hold_id)
            if hold is None or hold["status"] != "ACTIVE":
                return hold
            hold["status"] = "RELEASED"
            hold["released_at"] = datetime.now(timezone.utc).isoformat()
            hold["released_by"] = released_by
            self._active_keys.discard(
                self._key(hold.get("session_id") or hold.get("framework"), hold["trigger_type"])
            )
            self._active_keys.discard(self._key(hold.get("session_id"), hold["trigger_type"]))
            self._active_keys.discard(self._key(hold.get("framework"), hold["trigger_type"]))
            return hold

    def active_count(self) -> int:
        with self._lock:
            return len(self._active_keys)

    def reset(self) -> None:
        with self._lock:
            self._holds.clear()
            self._active_keys.clear()


legal_hold_manager = LegalHoldManager()
