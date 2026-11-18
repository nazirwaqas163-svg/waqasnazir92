"""Validation helpers for tenant-scoped OpenTelemetry-style span ingestion."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Dict


_TRACE_ID = re.compile(r"^[0-9a-fA-F]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-fA-F]{16}$")
_MAX_JSON_BYTES = 64 * 1024


def _timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.isoformat()


def normalize_span(span: Dict[str, Any], org_id: str) -> Dict[str, Any]:
    """Validate an OTel-shaped span and attach the verified tenant identity."""
    if not isinstance(span, dict):
        raise ValueError("Each span must be an object")
    trace_id = span.get("trace_id")
    span_id = span.get("span_id")
    parent_span_id = span.get("parent_span_id")
    if not isinstance(trace_id, str) or not _TRACE_ID.fullmatch(trace_id) or trace_id == "0" * 32:
        raise ValueError("trace_id must be a non-zero 32-character hexadecimal ID")
    if not isinstance(span_id, str) or not _SPAN_ID.fullmatch(span_id) or span_id == "0" * 16:
        raise ValueError("span_id must be a non-zero 16-character hexadecimal ID")
    if parent_span_id is not None and (
        not isinstance(parent_span_id, str)
        or not _SPAN_ID.fullmatch(parent_span_id)
        or parent_span_id == "0" * 16
    ):
        raise ValueError("parent_span_id must be a non-zero 16-character hexadecimal ID")
    name = span.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 512:
        raise ValueError("name must contain 1 to 512 characters")
    started_at = _timestamp(span.get("started_at"), "started_at")
    ended_at = _timestamp(span.get("ended_at"), "ended_at")
    if datetime.fromisoformat(ended_at) < datetime.fromisoformat(started_at):
        raise ValueError("ended_at must be greater than or equal to started_at")
    attributes = span.get("attributes", {})
    resource = span.get("resource", {})
    events = span.get("events", [])
    if not isinstance(attributes, dict) or not isinstance(resource, dict) or not isinstance(events, list):
        raise ValueError("attributes and resource must be objects and events must be an array")
    for field, value in (("attributes", attributes), ("resource", resource), ("events", events)):
        if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > _MAX_JSON_BYTES:
            raise ValueError(f"{field} exceeds the 64 KB limit")
    status = span.get("status", "unset")
    if not isinstance(status, str) or status not in {"unset", "ok", "error"}:
        raise ValueError("status must be unset, ok, or error")
    kind = span.get("kind", "internal")
    if not isinstance(kind, str) or kind not in {"internal", "server", "client", "producer", "consumer"}:
        raise ValueError("kind is not a supported span kind")
    agent_id = span.get("agent_id")
    if agent_id is not None and (not isinstance(agent_id, str) or len(agent_id) > 256):
        raise ValueError("agent_id must be a string of at most 256 characters")
    return {
        "org_id": org_id,
        "trace_id": trace_id.lower(),
        "span_id": span_id.lower(),
        "parent_span_id": parent_span_id.lower() if parent_span_id else None,
        "name": name.strip(),
        "kind": kind,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": status,
        "agent_id": agent_id,
        "resource": resource,
        "attributes": attributes,
        "events": events,
    }

