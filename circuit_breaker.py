from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


@dataclass
class KillSwitchEvent:
    state: CircuitState
    reason: str
    bdi_score: float
    entropy: float
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "reason": self.reason,
            "bdi_score": self.bdi_score,
            "entropy": self.entropy,
            "timestamp": self.timestamp,
        }


StateListener = Callable[[KillSwitchEvent], None]


class CircuitBreakerMiddleware:
    def __init__(
        self,
        bdi_threshold: float = 0.65,
        entropy_threshold: float = 0.85,
        reset_timeout_seconds: int = 30,
    ):
        self.state: CircuitState = CircuitState.CLOSED
        self.bdi_threshold = bdi_threshold
        self.entropy_threshold = entropy_threshold
        self.reset_timeout_seconds = reset_timeout_seconds
        self.last_event: Optional[KillSwitchEvent] = None
        self.failure_count: int = 0
        self.last_failure: Optional[dict[str, object]] = None
        self._listeners: List[StateListener] = []

    def register_listener(self, listener: StateListener) -> None:
        if listener not in self._listeners:
            self._listeners.append(listener)

    def unregister_listener(self, listener: StateListener) -> None:
        if listener in self._listeners:
            self._listeners.remove(listener)

    def _emit(self, event: KillSwitchEvent) -> None:
        self.last_event = event
        for listener in list(self._listeners):
            listener(event)

    def allows_requests(self) -> bool:
        return self.state == CircuitState.CLOSED

    def open(self, reason: str, bdi_score: float, entropy: float) -> None:
        if self.state != CircuitState.OPEN:
            self.state = CircuitState.OPEN
            self.failure_count += 1
            self.last_failure = {
                "reason": reason,
                "bdi_score": bdi_score,
                "entropy": entropy,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._emit(KillSwitchEvent(state=self.state, reason=reason, bdi_score=bdi_score, entropy=entropy))

    def close(self, reason: str, bdi_score: float, entropy: float) -> None:
        if self.state != CircuitState.CLOSED:
            self.state = CircuitState.CLOSED
            self._emit(KillSwitchEvent(state=self.state, reason=reason, bdi_score=bdi_score, entropy=entropy))

    def half_open(self, reason: str, bdi_score: float, entropy: float) -> None:
        """Deprecated: half-open auto-recovery is disabled; use close() to reset."""
        self.open(reason=reason or "half-open state treated as open", bdi_score=bdi_score, entropy=entropy)

    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN

    def is_half_open(self) -> bool:
        return self.state == CircuitState.HALF_OPEN

    def is_closed(self) -> bool:
        return self.state == CircuitState.CLOSED

    def _blocked(self, reason: str) -> Dict[str, object]:
        return {
            "action": "block",
            "reason": reason,
            "state": self.state.value,
        }

    def evaluate(self, bdi_score: float, entropy: float) -> Dict[str, object]:
        if not self.allows_requests():
            return self._blocked(
                f"Circuit breaker is {self.state.value}; all requests are blocked until explicitly reset to closed."
            )

        if entropy > self.entropy_threshold:
            self.open(
                reason="Shannon entropy exceeded kill threshold",
                bdi_score=bdi_score,
                entropy=entropy,
            )
            return self._blocked("Governance kill switch engaged due to high entropy.")

        if bdi_score > self.bdi_threshold:
            self.open(
                reason="BDI exceeded governance threshold",
                bdi_score=bdi_score,
                entropy=entropy,
            )
            return self._blocked("Governance kill switch engaged due to elevated BDI.")

        return {
            "action": "proceed",
            "reason": "Circuit breaker is closed; request permitted.",
            "state": self.state.value,
        }

    def status(self) -> Dict[str, object]:
        return {
            "state": self.state.value,
            "allows_requests": self.allows_requests(),
            "failure_count": self.failure_count,
            "last_failure": self.last_failure,
        }
