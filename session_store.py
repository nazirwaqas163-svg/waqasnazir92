from __future__ import annotations
import math
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

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
        risk_keywords = ["override","ignore","bypass","disable","delete","drop","admin","root","execute","sudo","hack","inject","exfiltrate","leak","steal","exploit"]
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


class SessionStore:
    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}
        self._lock = threading.Lock()

    def record_turn(self, session_id: str, agent_id: str, input_text: str, output_text: str) -> float:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(session_id=session_id, agent_id=agent_id)
            return self._sessions[session_id].record_turn(input_text, output_text)

    def active_sessions_for_agent(self, agent_id: str, window_seconds: int = 300) -> list[str]:
        """Return session_ids for agent active within the last window_seconds.
        Used for lightweight sync swarm detection inside /intercept."""
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

    def reset(self):
        with self._lock:
            self._sessions.clear()


session_store = SessionStore()
