"""
DriftEngine — session-window drift detection for Pulse.

5-component entropy drift score:
  output_drift        30%
  input_anomaly       25%
  confidence_variance 20%
  token_collapse      15%
  latency             10%

Thresholds:
  stable    < 0.40
  elevated  0.40 	6 0.69
  critical  >= 0.70
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple


WEIGHTS = {
    "output_drift": 0.30,
    "input_anomaly": 0.25,
    "confidence_variance": 0.20,
    "token_collapse": 0.15,
    "latency": 0.10,
}

STABLE_THRESHOLD = 0.40
ELEVATED_THRESHOLD = 0.70


@dataclass
class TurnRecord:
    input_text: str
    output_text: str
    latency_ms: float
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1.0
    return min(1.0, entropy / max_entropy)


def _token_diversity(text: str) -> float:
    if not text:
        return 0.0
    tokens = text.lower().split()
    if not tokens:
        return 0.0
    return min(1.0, len(set(tokens)) / len(tokens))


class SessionDriftWindow:
    """Sliding window of turns for a single session."""

    def __init__(self, window_size: int = 10) -> None:
        self._turns: Deque[TurnRecord] = deque(maxlen=window_size)
        self._lock = threading.Lock()

    def add_turn(self, turn: TurnRecord) -> None:
        with self._lock:
            self._turns.append(turn)

    def compute_drift(self) -> Dict[str, Any]:
        with self._lock:
            turns = list(self._turns)

        if not turns:
            return _zero_drift()

        # output_drift 	6 entropy variance across output texts
        output_entropies = [_shannon_entropy(t.output_text) for t in turns]
        output_drift = _variance(output_entropies)

        # input_anomaly 	6 latest input entropy vs window mean
        input_entropies = [_shannon_entropy(t.input_text) for t in turns]
        if len(input_entropies) > 1:
            window_mean = sum(input_entropies[:-1]) / len(input_entropies[:-1])
            input_anomaly = min(1.0, abs(input_entropies[-1] - window_mean) * 2)
        else:
            input_anomaly = input_entropies[0] if input_entropies else 0.0

        # confidence_variance 	6 token diversity variance
        diversities = [_token_diversity(t.output_text) for t in turns]
        confidence_variance = _variance(diversities)

        # token_collapse 	6 low diversity in latest output
        latest_diversity = _token_diversity(turns[-1].output_text) if turns else 1.0
        token_collapse = max(0.0, 1.0 - latest_diversity)

        # latency 	6 normalized latency spike
        latencies = [t.latency_ms for t in turns]
        if len(latencies) > 1:
            mean_latency = sum(latencies[:-1]) / len(latencies[:-1])
            latency_score = min(1.0, latencies[-1] / (mean_latency + 1) - 1.0) if mean_latency > 0 else 0.0
            latency_score = max(0.0, latency_score)
        else:
            latency_score = 0.0

        components = {
            "output_drift": round(output_drift, 4),
            "input_anomaly": round(input_anomaly, 4),
            "confidence_variance": round(confidence_variance, 4),
            "token_collapse": round(token_collapse, 4),
            "latency": round(latency_score, 4),
        }

        score = sum(components[k] * WEIGHTS[k] for k in WEIGHTS)
        score = min(1.0, max(0.0, score))

        if score >= ELEVATED_THRESHOLD:
            status = "critical"
        elif score >= STABLE_THRESHOLD:
            status = "elevated"
        else:
            status = "stable"

        return {
            "score": round(score, 4),
            "status": status,
            "components": components,
            "turns_analyzed": len(turns),
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }


class DriftEngine:
    """Manages per-session drift windows and exposes drift scores."""

    def __init__(self, window_size: int = 10) -> None:
        self._sessions: Dict[str, SessionDriftWindow] = {}
        self._lock = threading.Lock()
        self._window_size = window_size

    def record_turn(
        self,
        session_id: str,
        input_text: str,
        output_text: str,
        latency_ms: float = 0.0,
    ) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionDriftWindow(self._window_size)
            window = self._sessions[session_id]

        turn = TurnRecord(
            input_text=input_text,
            output_text=output_text,
            latency_ms=latency_ms,
        )
        window.add_turn(turn)
        return window.compute_drift()

    def get_drift(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            window = self._sessions.get(session_id)
        if window is None:
            return _zero_drift()
        return window.compute_drift()

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()

    def session_ids(self) -> List[str]:
        with self._lock:
            return list(self._sessions.keys())


def _variance(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return min(1.0, sum((v - mean) ** 2 for v in values) / len(values))


def _zero_drift() -> Dict[str, Any]:
    return {
        "score": 0.0,
        "status": "stable",
        "components": {k: 0.0 for k in WEIGHTS},
        "turns_analyzed": 0,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


drift_engine = DriftEngine()
