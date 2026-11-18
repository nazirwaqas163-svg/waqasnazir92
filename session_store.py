from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ----------------------------------------------------------------------
# BDI risk signals (FP-3)
# ----------------------------------------------------------------------
_INPUT_RISK_PATTERNS = {
    "override": r"\boverrid(?:e|es|ing)\b",
    "ignore_instructions": r"\bignore\s+(?:all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+)+(?:instructions?|rules?|polic(?:y|ies)|guidelines?)",
    "bypass": r"\bbypass(?:es|ing)?\b",
    "disable_security": r"\bdisabl(?:e|es|ing)\s+(?:the\s+|all\s+|any\s+)?(?:security|safety|guard|guardrails?|logging|audit|monitoring|filters?|policy|policies)",
    "sudo": r"\bsudo\b",
    "root_access": r"\broot\s+(?:access|shell|privileges?|password)",
    "admin_credentials": r"\badmin(?:istrator)?\s+(?:password|credentials?|access|token)",
    "exfiltrate": r"\bexfiltrat(?:e|es|ing|ion)\b",
    "steal": r"\bsteal(?:s|ing)?\b",
    "leak": r"\bleak(?:s|ing)?\s+(?:the\s+|all\s+|any\s+|customer\s+|user\s+)?(?:data|records?|passwords?|credentials?|keys?|secrets?|pii)",
    "exploit": r"\bexploit(?:s|ing)?\b",
    "hack": r"\bhack(?:s|ing|ed)?\b",
    "inject": r"\b(?:sql\s+|prompt\s+|code\s+)?inject(?:ion)?\b",
    "drop_table": r"\bdrop\s+(?:table|database|schema)\b",
    "delete_all": r"\b(?:delete|wipe|erase|purge)\s+(?:all|every|the\s+entire)\b",
    "dump_data": r"\b(?:dump|export|send|upload|forward)\s+(?:all|every|the\s+entire|the\s+full|complete)\s+(?:customer|user|client|database|records?|data|table|credentials?)",
    "system_prompt": r"\b(?:reveal|show|print|repeat|leak)\s+(?:your\s+|the\s+)?system\s+prompt\b",
    "credentials": r"\b(?:api[\s_-]?key|secret[\s_-]?key|private[\s_-]?key|access[\s_-]?token|password)s?\b.{0,30}\b(?:send|post|email|forward|paste|reveal|share|output)\b",
    "external_endpoint": r"\b(?:curl|wget|nc|netcat)\b\s+\S*(?:https?://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
}
_OUTPUT_RISK_PATTERNS = {
    "private_key_block": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
    "bearer_secret": r"\b(?:sk|pk|rk)[-_](?:live|test)?[-_]?[A-Za-z0-9]{20,}\b",
}
_INPUT_RE = {k: re.compile(v, re.I) for k, v in _INPUT_RISK_PATTERNS.items()}
_OUTPUT_RE = {k: re.compile(v) for k, v in _OUTPUT_RISK_PATTERNS.items()}


def _risk_hits(text: str, patterns=None) -> set:
    if not text:
        return set()
    table = _OUTPUT_RE if patterns is _OUTPUT_RISK_PATTERNS else _INPUT_RE
    return {name for name, rx in table.items() if rx.search(text)}


def _normalized_char_entropy(text: str) -> float:
    """Normalised Shannon entropy of characters; 0.0 for <15 chars (FP-1 rule)."""
    text = text or ""
    if len(text.strip()) < 15:
        return 0.0
    freq: dict = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    max_ent = math.log2(len(freq)) if len(freq) > 1 else 1.0
    return ent / max_ent if max_ent > 0 else 0.0


@dataclass
class SessionState:
    session_id: str
    agent_id: str
    turn_count: int = 0
    bdi_score: float = 0.0
    _seen_risk: set = field(default_factory=set, repr=False)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def record_turn(self, input_text: str, output_text: str) -> float:
        """Update and return the session's behavioural-deviation index (0..1).

        FP-3 rewrite: the old version added ~0.55 of raw character entropy on every
        turn with no decay, so any English session saturated at 1.0 by turn 2.
        Now the score moves only on real risk signals and relaxes on clean turns:
          * risk phrases in the input (whole-word match) raise it,
          * near-random input (encoded blobs / payloads) raises it slightly,
          * a clean turn decays it, so benign sessions settle near zero.
        """
        self.turn_count += 1
        self.last_seen = datetime.now(timezone.utc).isoformat()
        text = input_text or ""
        out = output_text or ""

        hits = _risk_hits(text)
        # Echoed secrets/credentials in the model output are a strong signal too.
        out_hits = _risk_hits(out, _OUTPUT_RISK_PATTERNS)

        increment = 0.0
        if hits:
            increment += min(0.45, 0.14 * len(hits))
            # Repeating the same risk behaviour across turns compounds.
            repeats = len(hits & self._seen_risk)
            increment += min(0.20, 0.08 * repeats)
            self._seen_risk |= hits
        if out_hits:
            increment += min(0.30, 0.15 * len(out_hits))
        # Encoded / near-random payloads (base64, hex dumps). Normal English
        # sits around 0.80-0.90 normalised character entropy; only the extreme
        # tail contributes.
        ent = _normalized_char_entropy(text)
        if ent > 0.95:
            increment += min(0.15, (ent - 0.95) * 3.0)

        if increment > 0.0:
            self.bdi_score = min(1.0, self.bdi_score + increment)
        else:
            # Clean turn: relax toward zero.
            self.bdi_score = max(0.0, self.bdi_score * 0.80 - 0.01)
        return self.bdi_score

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "turn_count": self.turn_count,
            "bdi_score": round(self.bdi_score, 4),
        }

    def to_persisted_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "turn_count": self.turn_count,
            "bdi_score": round(self.bdi_score, 8),
            "seen_risk": sorted(self._seen_risk),
            "created_at": self.created_at,
            "last_seen_at": self.last_seen,
        }

    @classmethod
    def from_persisted_dict(cls, row: Dict[str, Any]) -> "SessionState":
        return cls(
            session_id=str(row["session_id"]),
            agent_id=str(row["agent_id"]),
            turn_count=int(row.get("turn_count", 0)),
            bdi_score=float(row.get("bdi_score", 0.0)),
            _seen_risk=set(row.get("seen_risk") or []),
            created_at=str(row.get("created_at") or datetime.now(timezone.utc).isoformat()),
            last_seen=str(row.get("last_seen_at") or datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class IsolationRecord:
    """Tracks a quarantined agent — Phase 7 Stage 3."""
    org_id: str
    agent_id: str
    reason: str
    hold_id: Optional[str]
    isolated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    released_at: Optional[str] = None
    released_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "org_id": self.org_id,
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
        self._sessions: Dict[tuple[str, str], SessionState] = {}
        self._isolated: Dict[tuple[str, str], IsolationRecord] = {}   # (org_id, agent_id) -> record
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Session tracking (unchanged)
    # ------------------------------------------------------------------

    def record_turn(
        self, session_id: str, agent_id: str, input_text: str, output_text: str,
        org_id: str = "global",
    ) -> float:
        with self._lock:
            key = (org_id, session_id)
            if key not in self._sessions:
                self._sessions[key] = SessionState(
                    session_id=session_id, agent_id=agent_id
                )
            return self._sessions[key].record_turn(input_text, output_text)

    def active_sessions_for_agent(
        self, agent_id: str, window_seconds: int = 300, org_id: Optional[str] = None
    ) -> List[str]:
        """Return session_ids for agent active within the last window_seconds."""
        now = datetime.now(timezone.utc)
        result = []
        with self._lock:
            for (session_org_id, sid), state in self._sessions.items():
                if org_id is not None and session_org_id != org_id:
                    continue
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
        org_id: str = "global",
    ) -> IsolationRecord:
        """Quarantine an agent. All future /intercept calls return 423.
        If the agent is already isolated, returns the existing record."""
        with self._lock:
            key = (org_id, agent_id)
            existing = self._isolated.get(key)
            if existing and existing.released_at is None:
                return existing
            record = IsolationRecord(
                org_id=org_id,
                agent_id=agent_id,
                reason=reason,
                hold_id=hold_id,
            )
            self._isolated[key] = record
            return record

    def release_agent(
        self,
        agent_id: str,
        released_by: str = "manual",
        org_id: str = "global",
    ) -> Optional[IsolationRecord]:
        """Release an agent from isolation. Returns None if not found."""
        with self._lock:
            record = self._isolated.get((org_id, agent_id))
            if record is None:
                return None
            record.released_at = datetime.now(timezone.utc).isoformat()
            record.released_by = released_by
            return record

    def is_isolated(self, agent_id: str, org_id: str = "global") -> bool:
        """True if the agent is currently quarantined."""
        with self._lock:
            record = self._isolated.get((org_id, agent_id))
            return record is not None and record.released_at is None

    def get_isolation(self, agent_id: str, org_id: str = "global") -> Optional[IsolationRecord]:
        """Return the isolation record for an agent, or None."""
        with self._lock:
            return self._isolated.get((org_id, agent_id))

    def list_isolated(self, active_only: bool = True, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all isolation records."""
        with self._lock:
            records = list(self._isolated.values())
        if org_id is not None:
            records = [r for r in records if r.org_id == org_id]
        if active_only:
            records = [r for r in records if r.released_at is None]
        records.sort(key=lambda r: r.isolated_at, reverse=True)
        return [r.to_dict() for r in records]

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._isolated.clear()


session_store = SessionStore()

