from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


class RequestAction(str, Enum):
    PROCEED = "proceed"
    DROP = "drop"
    TRIP_DROP = "trip_drop"


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
        bdi_threshold: float = 0.85,
        entropy_threshold: float = 0.95,
        agent_cooldown_seconds: float = 30.0,
        minimum_calls: int = 5,
    ):
        self.state: CircuitState = CircuitState.CLOSED
        self.bdi_threshold = bdi_threshold
        self.entropy_threshold = entropy_threshold
        self.agent_cooldown_seconds = agent_cooldown_seconds
        self.minimum_calls = minimum_calls
        self.last_event: Optional[KillSwitchEvent] = None
        self.failure_count: int = 0
        self.last_failure: Optional[dict[str, object]] = None
        self._listeners: List[StateListener] = []
        self._lock = threading.RLock()
        self._agent_cooldown_until: Dict[str, float] = {}
        self._intercept_calls: int = 0

    def register_listener(self, listener: StateListener) -> None:
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def unregister_listener(self, listener: StateListener) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def _emit(self, event: KillSwitchEvent) -> None:
        self.last_event = event
        for listener in list(self._listeners):
            listener(event)

    def _agent_key(self, agent_id: Optional[str]) -> str:
        return (agent_id or "").strip() or "__anonymous__"

    def _prune_expired_cooldowns(self, now: float) -> None:
        expired = [key for key, until in self._agent_cooldown_until.items() if until <= now]
        for key in expired:
            del self._agent_cooldown_until[key]

    def allows_requests(self) -> bool:
        with self._lock:
            return self.state == CircuitState.CLOSED

    def open(self, reason: str, bdi_score: float, entropy: float) -> None:
        with self._lock:
            if self.state != CircuitState.OPEN:
                self.state = CircuitState.OPEN
                self.failure_count += 1
                self.last_failure = {
                    "reason": reason,
                    "bdi_score": bdi_score,
                    "entropy": entropy,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self._emit(
                    KillSwitchEvent(
                        state=self.state,
                        reason=reason,
                        bdi_score=bdi_score,
                        entropy=entropy,
                    )
                )

    def close(self, reason: str, bdi_score: float, entropy: float) -> None:
        with self._lock:
            if self.state != CircuitState.CLOSED:
                self.state = CircuitState.CLOSED
                self._agent_cooldown_until.clear()
                self._intercept_calls = 0
                self._emit(
                    KillSwitchEvent(
                        state=self.state,
                        reason=reason,
                        bdi_score=bdi_score,
                        entropy=entropy,
                    )
                )

    def half_open(self, reason: str, bdi_score: float, entropy: float) -> None:
        """Deprecated: half-open auto-recovery is disabled; use close() to reset."""
        self.open(reason=reason or "half-open state treated as open", bdi_score=bdi_score, entropy=entropy)

    def is_open(self) -> bool:
        with self._lock:
            return self.state == CircuitState.OPEN

    def is_half_open(self) -> bool:
        with self._lock:
            return self.state == CircuitState.HALF_OPEN

    def is_closed(self) -> bool:
        with self._lock:
            return self.state == CircuitState.CLOSED

    def _drop(
        self,
        reason: str,
        *,
        agent_id: Optional[str] = None,
        cooldown_active: bool = False,
        cooldown_seconds_remaining: float = 0.0,
    ) -> Dict[str, object]:
        return {
            "action": RequestAction.DROP.value,
            "reason": reason,
            "state": self.state.value,
            "agent_id": agent_id,
            "cooldown_active": cooldown_active,
            "cooldown_seconds_remaining": round(max(0.0, cooldown_seconds_remaining), 2),
        }

    def _trip_drop(self, reason: str) -> Dict[str, object]:
        return {
            "action": RequestAction.TRIP_DROP.value,
            "reason": reason,
            "state": self.state.value,
        }

    def _proceed(self, **extra: object) -> Dict[str, object]:
        result: Dict[str, object] = {
            "action": RequestAction.PROCEED.value,
            "reason": "Circuit breaker is closed; request permitted.",
            "state": self.state.value,
        }
        result.update(extra)
        return result

    def _shadow_proceed(self, would_have: Dict[str, object]) -> Dict[str, object]:
        """Observe-only path: traffic proceeds; metadata records what would have happened."""
        return self._proceed(
            shadow_mode=True,
            would_have_action=would_have.get("action"),
            would_have_reason=would_have.get("reason"),
            would_have_state=would_have.get("state"),
        )

    def _handle_open_locked(self, agent_id: Optional[str], now: float) -> Dict[str, object]:
        """Drop requests while open; enforce per-agent cooldown to ignore retries."""
        key = self._agent_key(agent_id)
        self._prune_expired_cooldowns(now)
        cooldown_until = self._agent_cooldown_until.get(key)

        if cooldown_until is not None and now < cooldown_until:
            return self._drop(
                "Request ignored: agent is in cooldown while circuit breaker is open.",
                agent_id=agent_id,
                cooldown_active=True,
                cooldown_seconds_remaining=cooldown_until - now,
            )

        self._agent_cooldown_until[key] = now + self.agent_cooldown_seconds
        return self._drop(
            "Request dropped: circuit breaker is open.",
            agent_id=agent_id,
            cooldown_active=False,
            cooldown_seconds_remaining=self.agent_cooldown_seconds,
        )

    def _record_intercept_call_locked(self) -> None:
        self._intercept_calls += 1

    def _bdi_warming_up_locked(self, *, intercept: bool) -> bool:
        return intercept and self._intercept_calls < self.minimum_calls

    def gate_request(
        self,
        *,
        agent_id: Optional[str],
        bdi_score: float,
        entropy: float,
        shadow_mode: bool = False,
        intercept: bool = False,
    ) -> Dict[str, object]:
        """
        Thread-safe entry point for concurrent proxy requests.

        When OPEN: drops requests (never returns a retryable 409-style outcome).
        Applies a per-agent cooldown window while open.

        BDI tripping is deferred until at least minimum_calls intercept requests
        have been recorded (cold-start / low-traffic protection).

        When shadow_mode is True, governance is evaluated but state is not mutated
        and traffic is always allowed through (would-block metadata is attached).
        """
        with self._lock:
            now = time.monotonic()

            if intercept:
                self._record_intercept_call_locked()

            if self.state != CircuitState.CLOSED:
                would_have = self._handle_open_locked(agent_id, now)
                if shadow_mode:
                    return self._shadow_proceed(would_have)
                return would_have

                self.open(
                    reason="Shannon entropy exceeded kill threshold",
                    bdi_score=bdi_score,
                    entropy=entropy,
                )
                return would_have

            if bdi_score > self.bdi_threshold and not self._bdi_warming_up_locked(intercept=intercept):
                would_have = self._trip_drop("Governance kill switch engaged due to elevated BDI.")
                if shadow_mode:
                    return self._shadow_proceed(would_have)
                self.open(
                    reason="BDI exceeded governance threshold",
                    bdi_score=bdi_score,
                    entropy=entropy,
                )
                return would_have

            extra: Dict[str, object] = {}
            if intercept and self._bdi_warming_up_locked(intercept=intercept):
                extra["bdi_warming_up"] = True
                extra["intercept_calls"] = self._intercept_calls
                extra["minimum_calls"] = self.minimum_calls

            if shadow_mode:
                return self._proceed(shadow_mode=shadow_mode, **extra)
            return self._proceed(**extra)

    def evaluate(
        self,
        bdi_score: float,
        entropy: float,
        agent_id: Optional[str] = None,
        shadow_mode: bool = False,
        intercept: bool = False,
    ) -> Dict[str, object]:
        """Backward-compatible wrapper around gate_request."""
        return self.gate_request(
            agent_id=agent_id,
            bdi_score=bdi_score,
            entropy=entropy,
            shadow_mode=shadow_mode,
            intercept=intercept,
        )

    def status(self) -> Dict[str, object]:
        with self._lock:
            now = time.monotonic()
            active_cooldowns = sum(1 for until in self._agent_cooldown_until.values() if until > now)
            return {
                "state": self.state.value,
                "allows_requests": self.state == CircuitState.CLOSED,
                "failure_count": self.failure_count,
                "last_failure": self.last_failure,
                "agent_cooldown_seconds": self.agent_cooldown_seconds,
                "active_agent_cooldowns": active_cooldowns,
                "bdi_threshold": self.bdi_threshold,
                "minimum_calls": self.minimum_calls,
                "intercept_calls": self._intercept_calls,
            }
