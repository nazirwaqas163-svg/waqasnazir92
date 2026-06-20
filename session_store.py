from __future__ import annotations
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
        increment = 0.08
        if len(output_text) > 500:
            increment += 0.02
        risk_keywords = ["override","ignore","bypass","disable","delete","drop","admin","root","execute","sudo","hack","inject","exfiltrate","leak","steal","exploit"]
        if any(k in input_text.lower() for k in risk_keywords):
            increment += 0.05
        self.bdi_score = min(1.0, self.bdi_score + increment)
        return self.bdi_score

    def to_dict(self) -> dict:
        return {"session_id": self.session_id, "agent_id": self.agent_id, "turn_count": self.turn_count, "bdi_score": round(self.bdi_score, 4)}

class SessionStore:
    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}
        self._lock = threading.Lock()

    def record_turn(self, session_id: str, agent_id: str, input_text: str, output_text: str) -> float:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(session_id=session_id, agent_id=agent_id)
            return self._sessions[session_id].record_turn(input_text, output_text)

    def reset(self):
        with self._lock:
            self._sessions.clear()

session_store = SessionStore()
