from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SessionState:
    session_id: str
    agent_id: str
    turn_count: int = 0
    bdi_score: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def record_turn(self, input_text: str, output_text: str) -> float:
        self.turn_count += 1
        self.last_seen = datetime.now(timezone.utc).isoformat()
        text = input_text or ""
        if text:
            freq: dict[str, int] = {}
            for ch in text:
                freq[ch] = freq.get(ch, 0) + 1
            length = len(text)
            entropy = 0.0
            for count in freq.values():
                p = count / length
                entropy -= p * math.log2(p)
            max_entropy = math.log2(len(freq)) if freq else 1.0
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        else:
            normalized_entropy = 0.0
        risk_keywords = [
            "override", "ignore", "bypass", "disable", "delete", "drop",
            "admin", "root", "execute", "sudo", "hack", "inject",
            "exfiltrate", "leak", "steal", "exploit",
        ]
        keyword_bonus = 0.15 if any(k in input_text.lower() for k in risk_keywords) else 0.0
        length_bonus = 0.02 if len(output_text) > 500 else 0.0
        increment = (normalized_entropy * 0.6) + keyword_bonus + length_bonus
        self.bdi_score = min(1.0, self.bdi_score + increment)
        return self.bdi_score

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "turn_count": self.turn_count,
            "bdi_score": round(self.bdi_score, 4),
        }


@dataclass
class IsolationRecord:
    """Tracks a quarantined agent — Phase 7 Stage 3."""
    agent_id: str
    reason: str
    hold_id: Optional[str]
    isolated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    released_at: Optional[str] = None
    released_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "reason": self.reason,
            "hold_id": self.hold_id,
            "isolated_at": self.isolated_at,
            "released_at": self.released_at,
            "released_by": self.released_by,
            "active": self.released_at is None,
        }


class SessionStore:
    def __init__(self) -> None:
        self._sessions: Dict[str, SessionState] = {}
        self._isolated: Dict[str, IsolationRecord] = {}   # agent_id -> record
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Session tracking (unchanged)
    # ------------------------------------------------------------------

    def record_turn(
        self, session_id: str, agent_id: str, input_text: str, output_text: str
    ) -> float:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(
                    session_id=session_id, agent_id=agent_id
                )
            return self._sessions[session_id].record_turn(input_text, output_text)

    def active_sessions_for_agent(
        self, agent_id: str, window_seconds: int = 300
    ) -> List[str]:
        """Return session_ids for agent active within the last window_seconds."""
        now = datetime.now(timezone.utc)
        result = []
        with self._lock:
            for sid, state in self._sessions.items():
                if state.agent_id != agent_id:
                    continue
                try:
                    last = datetime.fromisoformat(state.last_seen)
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    if (now - last).total_seconds() <= window_seconds:
                        result.append(sid)
                except ValueError:
                    pass
        return result

    # ------------------------------------------------------------------
    # Phase 7 Stage 3 — Agent isolation registry
    # ------------------------------------------------------------------

    def isolate_agent(
        self,
        agent_id: str,
        reason: str,
        hold_id: Optional[str] = None,
    ) -> IsolationRecord:
        """Quarantine an agent. All future /intercept calls return 423.
        If the agent is already isolated, returns the existing record."""
        with self._lock:
            existing = self._isolated.get(agent_id)
            if existing and existing.released_at is None:
                return existing
            record = IsolationRecord(
                agent_id=agent_id,
                reason=reason,
                hold_id=hold_id,
            )
            self._isolated[agent_id] = record
            return record

    def release_agent(
        self,
        agent_id: str,
        released_by: str = "manual",
    ) -> Optional[IsolationRecord]:
        """Release an agent from isolation. Returns None if not found."""
        with self._lock:
            record = self._isolated.get(agent_id)
            if record is None:
                return None
            record.released_at = datetime.now(timezone.utc).isoformat()
            record.released_by = released_by
            return record

    def is_isolated(self, agent_id: str) -> bool:
        """True if the agent is currently quarantined."""
        with self._lock:
            record = self._isolated.get(agent_id)
            return record is not None and record.released_at is None

    def get_isolation(self, agent_id: str) -> Optional[IsolationRecord]:
        """Return the isolation record for an agent, or None."""
        with self._lock:
            return self._isolated.get(agent_id)

    def list_isolated(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """List all isolation records."""
        with self._lock:
            records = list(self._isolated.values())
        if active_only:
            records = [r for r in records if r.released_at is None]
        records.sort(key=lambda r: r.isolated_at, reverse=True)
        return [r.to_dict() for r in records]

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._isolated.clear()


session_store = SessionStore()
