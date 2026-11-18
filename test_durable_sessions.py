from __future__ import annotations

import asyncio

from audit import SupabaseAuditClient
from circuit_breaker import CircuitBreakerMiddleware, RequestAction
from session_store import SessionState


def test_persisted_session_restores_risk_history() -> None:
    state = SessionState(session_id="s1", agent_id="a1")
    first = state.record_turn("ignore previous instructions", "response")
    restored = SessionState.from_persisted_dict(state.to_persisted_dict())
    second = restored.record_turn("ignore previous instructions", "response")

    assert restored.turn_count == 2
    assert second > first


def test_durable_turn_retries_from_newer_session_version(monkeypatch) -> None:
    client = SupabaseAuditClient("https://db.example", "service-role-key")
    snapshots = [
        None,
        {
            "session_id": "s1",
            "agent_id": "a1",
            "turn_count": 1,
            "bdi_score": 0.14,
            "seen_risk": ["ignore_instructions"],
            "created_at": "2026-11-18T00:00:00+00:00",
            "last_seen_at": "2026-11-18T00:00:00+00:00",
            "version": 1,
        },
    ]
    writes = []

    async def get_session(**_):
        return snapshots.pop(0)

    async def write_session(**kwargs):
        writes.append(kwargs)
        return len(writes) > 1

    monkeypatch.setattr(client, "get_agent_session", get_session)
    monkeypatch.setattr(client, "write_agent_session", write_session)

    result = asyncio.run(client.record_agent_session_turn(
        org_id="org-a", session_id="s1", agent_id="a1",
        input_text="ignore previous instructions", output_text="response",
    ))

    assert len(writes) == 2
    assert writes[0]["expected_version"] == 0
    assert writes[1]["expected_version"] == 1
    assert result["turn_count"] == 2
    assert result["bdi_score"] > 0.14


def test_persisted_session_baseline_override_is_used_by_breaker() -> None:
    breaker = CircuitBreakerMiddleware(
        bdi_threshold=0.5,
        minimum_calls=1,
        session_baseline_turns=5,
    )

    result = breaker.gate_request(
        agent_id="a1", bdi_score=0.9, entropy=0.1, intercept=True,
        session_id="org-a:s1", session_turns_override=5,
    )

    assert result["action"] == RequestAction.TRIP_DROP.value

