"""
Phase 4 Stage 3 — Threat Classification Layer
Computes discrete threat class scores for behavioral risk assessment.
Observation-only: scores appended to /intercept response, no blocking.
"""

from typing import Any, Dict, Optional


class ThreatClassifier:
    """Threat Classification Engine — Phase 4 Stage 3"""

    def __init__(self):
        self.baseline_min_turns = 5
        # Thresholds for individual threat scores (0.0–1.0)
        self.thresholds = {
            "exfiltration": 0.65,
            "unauthorized_spawn": 0.50,
            "scope_violation": 0.60,
            "swarm_activity": 0.50,
            "policy_violation": 0.40,
            "entropy_spike": 0.70,
        }

    def classify(
        self,
        *,
        exfiltration_risk: Optional[float] = None,
        unregistered: float = 0.0,
        unauthorized_spawn: float = 0.0,
        scope_violation: Optional[float] = None,
        swarm_suspect: bool = False,
        swarm_session_count: int = 0,
        drift_score: Optional[float] = None,
        entropy: float = 0.0,
        policy_blocked_turns: int = 0,
        policy_total_turns: int = 0,
        baselined: bool = False,
    ) -> Dict[str, Any]:
        """
        Compute threat classification vector across 6 threat classes.
        
        Args:
            exfiltration_risk: Pre-computed exfiltration risk score (0.0–1.0)
            unregistered: 1.0 if agent not in registry, else 0.0
            unauthorized_spawn: 1.0 if no parent_session_id, else 0.0
            scope_violation: Pre-computed scope violation score, or None
            swarm_suspect: Boolean flag from session-count check
            swarm_session_count: Active sessions for this agent in window
            drift_score: Drift engine composite score (0.0–1.0)
            entropy: Shannon entropy of input text (0.0–1.0)
            policy_blocked_turns: Number of blocked turns in session
            policy_total_turns: Total turns in session
            baselined: Whether drift engine has enough turns for baseline
        
        Returns:
            Dict with threat_scores, threat_flags, threat_level, etc.
        """
        threat_scores: Dict[str, float] = {}
        threat_flags: Dict[str, bool] = {}
        rationale: Dict[str, str] = {}

        # ===== THREAT 1: EXFILTRATION RISK =====
        exfiltration_score = exfiltration_risk if exfiltration_risk is not None else 0.0
        threat_scores["exfiltration"] = round(exfiltration_score, 4)
        threat_flags["exfiltration"] = exfiltration_score > self.thresholds["exfiltration"]
        rationale["exfiltration"] = (
            f"Token collapse + input anomaly: {exfiltration_score:.4f}. "
            f"Threshold: {self.thresholds['exfiltration']}. "
            f"High scores indicate semantic drift toward data-exfiltration patterns."
        )

        # ===== THREAT 2: UNAUTHORIZED SPAWN =====
        spawn_score = max(unregistered, unauthorized_spawn)
        threat_scores["unauthorized_spawn"] = round(spawn_score, 4)
        threat_flags["unauthorized_spawn"] = spawn_score > self.thresholds["unauthorized_spawn"]
        spawn_rationale = []
        if unregistered > 0.5:
            spawn_rationale.append("agent unregistered")
        if unauthorized_spawn > 0.5:
            spawn_rationale.append("no parent session (rootless)")
        rationale["unauthorized_spawn"] = (
            f"Spawn risk: {spawn_score:.4f} ({', '.join(spawn_rationale) if spawn_rationale else 'none'}). "
            f"Threshold: {self.thresholds['unauthorized_spawn']}. "
            f"Unregistered or rootless sessions cannot be traced to a parent context."
        )

        # ===== THREAT 3: SCOPE VIOLATION =====
        scope_score = scope_violation if scope_violation is not None else 0.0
        threat_scores["scope_violation"] = round(scope_score, 4)
        threat_flags["scope_violation"] = scope_score > self.thresholds["scope_violation"]
        rationale["scope_violation"] = (
            f"Scope violation: {scope_score:.4f}. Threshold: {self.thresholds['scope_violation']}. "
            f"Not yet measurable (agent scopes not registered). Will activate when scope baseline available."
        )

        # ===== THREAT 4: SWARM ACTIVITY =====
        swarm_score = 1.0 if swarm_suspect else 0.0
        threat_scores["swarm_activity"] = round(swarm_score, 4)
        threat_flags["swarm_activity"] = swarm_score > self.thresholds["swarm_activity"]
        rationale["swarm_activity"] = (
            f"Swarm risk: {swarm_score:.4f} ({swarm_session_count} active sessions in 5m window). "
            f"Threshold: {self.thresholds['swarm_activity']}. "
            f"Session count >= 3 indicates potential resource exhaustion or DoS."
        )

        # ===== THREAT 5: POLICY VIOLATION =====
        policy_score = 0.0
        if policy_total_turns > 0:
            blocked_ratio = policy_blocked_turns / policy_total_turns
            policy_score = min(1.0, blocked_ratio * 2.0)
        threat_scores["policy_violation"] = round(policy_score, 4)
        threat_flags["policy_violation"] = policy_score > self.thresholds["policy_violation"]
        rationale["policy_violation"] = (
            f"Policy risk: {policy_score:.4f} "
            f"({policy_blocked_turns} blocked / {policy_total_turns} total turns). "
            f"Threshold: {self.thresholds['policy_violation']}. "
            f"Persistent policy violations indicate intentional or systematic boundary crossing."
        )

        # ===== THREAT 6: ENTROPY SPIKE =====
        entropy_score = 0.0
        if drift_score is not None and baselined:
            if drift_score > 0.65:
                entropy_score = entropy * drift_score
            else:
                entropy_score = entropy * 0.5
            entropy_score = min(1.0, entropy_score)
        threat_scores["entropy_spike"] = round(entropy_score, 4)
        threat_flags["entropy_spike"] = entropy_score > self.thresholds["entropy_spike"]
        drift_status = "critical" if (drift_score or 0) > 0.65 else "normal" if baselined else "unbaselined"
        rationale["entropy_spike"] = (
            f"Entropy risk: {entropy_score:.4f} "
            f"(entropy={entropy:.4f}, drift={drift_status}). "
            f"Threshold: {self.thresholds['entropy_spike']}. "
            f"Compounded signal: high entropy + drift suggests behavioral anomaly."
        )

        # ===== THREAT LEVEL (CATEGORICAL) =====
        fired_threats = [k for k, v in threat_flags.items() if v]
        threat_count = len(fired_threats)

        if threat_count >= 3:
            threat_level = "CRITICAL"
        elif threat_count == 2:
            threat_level = "HIGH"
        elif threat_count == 1:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        return {
            "threat_scores": threat_scores,
            "threat_flags": threat_flags,
            "threat_level": threat_level,
            "fired_threats": fired_threats,
            "fired_count": threat_count,
            "rationale": rationale,
        }


threat_classifier = ThreatClassifier()
