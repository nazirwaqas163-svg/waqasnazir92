"""Behavior checks for benign traffic and clear threat signals."""

from threat_classifier import ThreatClassifier


def test_new_clean_session_does_not_flag_missing_baseline_as_threat() -> None:
    result = ThreatClassifier().classify(
        exfiltration_risk=0.95,
        unregistered=1.0,
        unauthorized_spawn=1.0,
        drift_score=0.9,
        entropy=1.0,
        baselined=False,
    )

    assert result["threat_flags"]["exfiltration"] is False
    assert result["threat_flags"]["unauthorized_spawn"] is False
    assert result["threat_flags"]["entropy_spike"] is False
    assert result["threat_level"] == "LOW"
    assert result["not_yet_measurable"]["exfiltration"] is True
    assert result["not_yet_measurable"]["unauthorized_spawn"] is True


def test_normal_baselined_traffic_is_not_flagged() -> None:
    result = ThreatClassifier().classify(
        exfiltration_risk=0.10,
        unregistered=0.0,
        unauthorized_spawn=0.0,
        swarm_suspect=False,
        drift_score=0.20,
        entropy=0.50,
        policy_blocked_turns=0,
        policy_total_turns=5,
        baselined=True,
    )

    assert result["fired_threats"] == []
    assert result["threat_level"] == "LOW"


def test_clear_exfiltration_signal_is_flagged_after_baseline() -> None:
    result = ThreatClassifier().classify(
        exfiltration_risk=0.90,
        unregistered=0.0,
        unauthorized_spawn=0.0,
        swarm_suspect=False,
        drift_score=0.80,
        entropy=0.90,
        baselined=True,
    )

    assert result["threat_flags"]["exfiltration"] is True
    assert result["threat_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
