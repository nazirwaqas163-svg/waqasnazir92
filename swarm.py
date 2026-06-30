"""
Swarm Detector — Phase 3 Stage 3.

Detects coordinated multi-agent / multi-session behaviour: the same output
fingerprint replicated across distinct sessions inside a time window. This is
how a single compromised agent fanning out across many sessions (the NovaTrans
exfiltration pattern) or several agents acting in concert surface as one event.

A cluster is MALICIOUS when it contains blocked turns, BENIGN_COORDINATION when
it does not. Only malicious clusters set swarm_detected.

Risk thresholds mirror the drift engine:  stable <0.40, elevated 0.40-0.69,
critical >=0.70.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

_WS = re.compile(r"\s+")
_TZ_SHORT = re.compile(r"([+-]\d{2})$")

STABLE_THRESHOLD = 0.40
ELEVATED_THRESHOLD = 0.70


def _parse_ts(raw: Any) -> Optional[datetime]:
    if not raw:
        return None
    s = str(raw).strip().replace("Z", "+00:00")
    if _TZ_SHORT.search(s):
        s = s + ":00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.fromisoformat(s.split(".")[0])
        except ValueError:
            return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def output_fingerprint(text: Optional[str]) -> str:
    norm = _WS.sub(" ", (text or "").strip().lower())
    if not norm:
        return "empty"
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:16]


def _status_from_risk(risk: float) -> str:
    if risk >= ELEVATED_THRESHOLD:
        return "critical"
    if risk >= STABLE_THRESHOLD:
        return "elevated"
    return "stable"


def _clamp(v: float) -> float:
    return min(1.0, max(0.0, v))


class SwarmDetector:
    def __init__(
        self,
        window_minutes: int = 60,
        min_cluster_size: int = 3,
        min_distinct_sessions: int = 2,
    ) -> None:
        self.window_minutes = window_minutes
        self.min_cluster_size = min_cluster_size
        self.min_distinct_sessions = min_distinct_sessions

    def detect(
        self,
        events: List[Dict[str, Any]],
        *,
        now: Optional[datetime] = None,
        window_minutes: Optional[int] = None,
        min_cluster_size: Optional[int] = None,
        min_distinct_sessions: Optional[int] = None,
    ) -> Dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        wm = window_minutes if window_minutes is not None else self.window_minutes
        min_size = min_cluster_size if min_cluster_size is not None else self.min_cluster_size
        min_sessions = (
            min_distinct_sessions if min_distinct_sessions is not None else self.min_distinct_sessions
        )
        cutoff = now - timedelta(minutes=wm)

        window: List[Dict[str, Any]] = []
        for e in events:
            dt = _parse_ts(e.get("created_at") or e.get("timestamp"))
            if dt is not None and dt >= cutoff:
                window.append(e)

        groups: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"events": [], "sessions": set(), "agents": set(), "blocked": 0, "sample": ""}
        )
        for e in window:
            fp = output_fingerprint(e.get("output_text"))
            if fp == "empty":
                continue
            g = groups[fp]
            g["events"].append(e)
            g["sessions"].add(e.get("session_id"))
            g["agents"].add(e.get("agent_id"))
            if e.get("status") == "blocked":
                g["blocked"] += 1
            if not g["sample"]:
                g["sample"] = (e.get("output_text") or "")[:160]

        clusters: List[Dict[str, Any]] = []
        for fp, g in groups.items():
            size = len(g["events"])
            sessions = {s for s in g["sessions"] if s}
            ds = len(sessions)
            da = len({a for a in g["agents"] if a})
            if size < min_size or ds < min_sessions:
                continue
            blocked_ratio = g["blocked"] / size if size else 0.0
            kind = "malicious_swarm" if g["blocked"] > 0 else "benign_coordination"
            risk = _clamp(
                0.45 * min(1.0, ds / 5.0)
                + 0.40 * blocked_ratio
                + 0.15 * min(1.0, size / 12.0)
            )
            clusters.append(
                {
                    "fingerprint": fp,
                    "kind": kind,
                    "size": size,
                    "distinct_sessions": ds,
                    "distinct_agents": da,
                    "blocked_turns": g["blocked"],
                    "blocked_ratio": round(blocked_ratio, 4),
                    "risk": round(risk, 4),
                    "status": _status_from_risk(risk),
                    "sample_output": g["sample"],
                    "session_ids": sorted(sessions),
                    "agent_ids": sorted({a for a in g["agents"] if a}),
                }
            )

        clusters.sort(key=lambda c: c["risk"], reverse=True)
        malicious = [c for c in clusters if c["kind"] == "malicious_swarm"]
        swarm_detected = any(
            c["distinct_sessions"] >= min_sessions and c["risk"] >= STABLE_THRESHOLD
            for c in malicious
        )
        if any(c["status"] == "critical" for c in malicious):
            overall = "critical"
        elif any(c["status"] == "elevated" for c in malicious):
            overall = "elevated"
        else:
            overall = "stable"

        return {
            "generated_at": now.isoformat(),
            "window_minutes": wm,
            "events_in_window": len(window),
            "swarm_detected": swarm_detected,
            "overall_status": overall,
            "clusters_found": len(clusters),
            "clusters": clusters,
        }


swarm_detector = SwarmDetector()
