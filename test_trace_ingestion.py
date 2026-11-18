from __future__ import annotations

import pytest

from trace_ingestion import normalize_span


def _span() -> dict:
    return {
        "trace_id": "0123456789abcdef0123456789abcdef",
        "span_id": "0123456789abcdef",
        "parent_span_id": None,
        "name": "agent.invoke",
        "kind": "internal",
        "started_at": "2026-11-18T10:00:00Z",
        "ended_at": "2026-11-18T10:00:01Z",
        "status": "ok",
        "agent_id": "agent-1",
        "resource": {"service.name": "sample-agent"},
        "attributes": {"gen_ai.operation.name": "chat"},
        "events": [],
    }


def test_normalize_span_scopes_tenant_and_normalizes_ids() -> None:
    span = _span()
    span["trace_id"] = span["trace_id"].upper()
    row = normalize_span(span, "org-123")
    assert row["org_id"] == "org-123"
    assert row["trace_id"] == "0123456789abcdef0123456789abcdef"
    assert row["started_at"].endswith("+00:00")


@pytest.mark.parametrize("field,value", [
    ("trace_id", "bad"),
    ("span_id", "0" * 16),
    ("started_at", "2026-11-18T10:00:00"),
    ("status", {}),
    ("kind", "unknown"),
])
def test_normalize_span_rejects_invalid_values(field: str, value: object) -> None:
    span = _span()
    span[field] = value
    with pytest.raises(ValueError):
        normalize_span(span, "org-123")


def test_normalize_span_rejects_oversized_attributes() -> None:
    span = _span()
    span["attributes"] = {"payload": "x" * (64 * 1024)}
    with pytest.raises(ValueError, match="64 KB"):
        normalize_span(span, "org-123")


def test_normalize_span_rejects_negative_duration() -> None:
    span = _span()
    span["ended_at"] = "2026-11-18T09:59:59Z"
    with pytest.raises(ValueError, match="ended_at"):
        normalize_span(span, "org-123")

