"""
Shadow Score v2 — Phase 3 Stage 4.

Canonical composite formula:
    shadow_score = unregistered × 0.40
                 + unauthorized_spawn × 0.35
                 + scope_violation × 0.25

Inputs:
  - unregistered       : agent has no identity in Pulse registry (0.0 or 1.0)
  - unauthorized_spawn : session has no valid parent_session_id linkage (0.0 or 1.0)
  - scope_violation    : agent acted outside declared scope (0.0 or 1.0)

scope_violation returns 0.0 with flag SCOPE_NOT_MEASURABLE when no real scopes
are registered. Weights stay fixed — the ceiling is 0.75 until scope data exists.
This is intentional and court-defensible: the formula never silently rebalances.

Thresholds (mirror drift engine):
  stable   < 0.40
  elevated 0.40 – 0.69
  critical >= 0.70

Build-rule compliance:
  - unauthorized_spawn requires live parent_session_id lineage. If lineage is
    not yet available, pass baselined=False → returns UNBASELINED flag, no score.
  - Never default any component to zero without an explicit flag.
"""

from __future__ import annotations
from typing import Any, Dict, Optional

W_UNREGISTERED = 0.40
W_UNAUTHORIZED_SPAWN = 0.35
W_SCOPE_VIOLATION = 0.25

STABLE_THRESHOLD = 0.40
ELEVATED_THRESHOLD = 0.70

UNDER_REPORT_THRESHOLD = 0.30
OVER_REPORT_THRESHOLD = 0.30


def _clamp(v: Optional[float]) -> float:
    if v is None:
        return 0.0
    return min(1.0, max(0.0, float(v)))


def _status(score: float) -> str:
    if score >= ELEVATED_THRESHOLD:
        return "critical"
    if score >= STABLE_THRESHOLD:
        return "elevated"
    return "stable"


def compute_shadow(
    unregistered: Optional[float],
    unauthorized_spawn: Optional[float],
    scope_violation: Optional[float] = None,
    *,
    baselined: bool = True,
    scope_measurable: bool = False,
) -> Dict[str, Any]:
    """
    Compute Shadow Score v2.

    Args:
        unregistered:       1.0 if agent not in registry, 0.0 if registered.
        unauthorized_spawn: 1.0 if session has no valid parent_session_id, 0.0 if linked.
                            Requires Stage 2 lineage to be live. Pass baselined=False
                            if lineage is not yet available.
        scope_violation:    1.0 if agent acted outside declared scope, 0.0 if within scope.
                            Pass None + scope_measurable=False if no scopes are registered.
        baselined:          False if parent_session_id lineage resolver is not live yet.
        scope_measurable:   True only when real agent scopes exist in registry.

    Returns:
        Dict with shadow_score, status, flag, components, weights.
    """
    u = _clamp(unregistered)
    s = _clamp(unauthorized_spawn)

    components: Dict[str, Any] = {
        "unregistered": round(u, 4),
        "unauthorized_spawn": round(s, 4),
        "scope_violation": None,
        "scope_measurable": scope_measurable,
    }
    weights: Dict[str, float] = {
        "unregistered": W_UNREGISTERED,
        "unauthorized_spawn": W_UNAUTHORIZED_SPAWN,
        "scope_violation": W_SCOPE_VIOLATION,
    }

    if not baselined:
        return {
            "shadow_score": None,
            "combined_score": None,
            "status": None,
            "flag": "UNBASELINED",
            "baselined": False,
            "note": "parent_session_id lineage not yet live. unauthorized_spawn cannot be measured.",
            "components": components,
            "weights": weights,
        }

    if not scope_measurable or scope_violation is None:
        sv = 0.0
        scope_flag = "SCOPE_NOT_MEASURABLE"
        components["scope_violation"] = 0.0
    else:
        sv = _clamp(scope_violation)
        scope_flag = None
        components["scope_violation"] = round(sv, 4)

    score = (
        (W_UNREGISTERED * u)
        + (W_UNAUTHORIZED_SPAWN * s)
        + (W_SCOPE_VIOLATION * sv)
    )
    score = round(min(1.0, max(0.0, score)), 4)

    flags = []
    if scope_flag:
        flags.append(scope_flag)
    if u >= 1.0:
        flags.append("UNREGISTERED")
    if s >= 1.0:
        flags.append("UNAUTHORIZED_SPAWN")
    if sv >= 1.0 and scope_measurable:
        flags.append("SCOPE_VIOLATED")

    primary_flag = flags[0] if flags else "CLEAN"

    return {
        "shadow_score": score,
        "combined_score": score,
        "status": _status(score),
        "flag": primary_flag,
        "all_flags": flags,
        "baselined": True,
        "note": "scope_violation fixed at 0.0 — no agent scopes registered yet. Max score 0.75." if scope_flag else None,
        "components": components,
        "weights": weights,
    }


def compute_trust_divergence(
    agent_self_report: Optional[float],
    pulse_independent: Optional[float],
    *,
    baselined: bool = True,
    w_agent: float = 0.60,
    w_pulse: float = 0.40,
) -> Dict[str, Any]:
    """
    Trust Divergence Score — separate from Shadow Score v2.
    Dual-channel: agent self-report vs Pulse independent measurement.
    shadow_score = |pulse - agent|
    UNDER_REPORTING is the dangerous direction — drives auto legal hold.
    """
    a = _clamp(agent_self_report)
    p = _clamp(pulse_independent)
    channels = {"agent_self_report": round(a, 4), "pulse_independent": round(p, 4)}
    weights = {"agent": w_agent, "pulse": w_pulse}

    if not baselined:
        return {
            "divergence_score": None,
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
        "divergence_score": round(abs(divergence), 4),
        "combined_risk": round(_clamp(combined), 4),
        "divergence": round(divergence, 4),
        "flag": flag,
        "baselined": True,
        "channels": channels,
        "weights": weights,
    }
