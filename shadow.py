"""
Shadow Score — Phase 3 Stage 4.

Dual-channel verification. Two independent risk signals:
  - agent self-report channel  (weight 0.60) — what the agent declares about itself
  - Pulse independent channel   (weight 0.40) — what Pulse measures regardless

combined_risk = 0.60*agent + 0.40*pulse   (reporting only)
shadow_score  = |pulse - agent|           (the divergence / safety net)

The dangerous direction is UNDER_REPORTING: Pulse sees materially more risk than
the agent admits. That flag — not combined_risk — is what drives auto legal hold,
so a lying self-report cannot mask Pulse's own signal.

Build-rule compliance: when the Pulse channel has no baseline yet (cold start,
zero drift turns) we return flag UNBASELINED rather than emitting a false ALIGNED
on zero data.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

W_AGENT = 0.60
W_PULSE = 0.40
UNDER_REPORT_THRESHOLD = 0.30
OVER_REPORT_THRESHOLD = 0.30


def _clamp(v: Optional[float]) -> float:
    if v is None:
        return 0.0
    return min(1.0, max(0.0, float(v)))


def compute_shadow(
    agent_self_report: Optional[float],
    pulse_independent: Optional[float],
    *,
    baselined: bool = True,
    w_agent: float = W_AGENT,
    w_pulse: float = W_PULSE,
) -> Dict[str, Any]:
    a = _clamp(agent_self_report)
    p = _clamp(pulse_independent)
    channels = {"agent_self_report": round(a, 4), "pulse_independent": round(p, 4)}
    weights = {"agent": w_agent, "pulse": w_pulse}

    if not baselined:
        return {
            "shadow_score": None,
            "combined_risk": None,
            "divergence": None,
            "flag": "UNBASELINED",
            "baselined": False,
            "channels": channels,
            "weights": weights,
        }

    combined = (w_agent * a) + (w_pulse * p)
    divergence = p - a
    if divergence >= UNDER_REPORT_THRESHOLD:
        flag = "UNDER_REPORTING"
    elif -divergence >= OVER_REPORT_THRESHOLD:
        flag = "OVER_REPORTING"
    else:
        flag = "ALIGNED"

    return {
        "shadow_score": round(abs(divergence), 4),
        "combined_risk": round(_clamp(combined), 4),
        "divergence": round(divergence, 4),
        "flag": flag,
        "baselined": True,
        "channels": channels,
        "weights": weights,
    }
