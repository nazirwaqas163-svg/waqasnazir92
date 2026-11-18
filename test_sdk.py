"""Unit tests for pulse_sdk — all HTTP mocked, no live calls."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import httpx
import pytest

from pulse_sdk import (
    GovernanceException,
    PulseCircuitTrippedException,
    PulseGuard,
    PulseResult,
)


def _mock_client() -> MagicMock:
    client = MagicMock()
    client.post = MagicMock()
    client.get = MagicMock()
    return client


def _ok_response(output_text: str = "hello") -> MagicMock:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.headers = {}
    response.json.return_value = {"ok": True, "output_text": output_text}
    return response


# ── existing tests (unchanged) ──────────────────────────────────────────────

@patch("pulse_sdk.httpx.Client")
def test_watch_decorator(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    mock_client.post.return_value = _ok_response("answer: ping")
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent")
    guard.new_session()

    @guard.watch()
    def greet(name: str) -> str:
        return f"answer: {name}"

    result = greet("ping")

    assert result == "answer: ping"
    mock_client.post.assert_called_once()
    call_kwargs = mock_client.post.call_args
    assert call_kwargs[0][0] == "http://127.0.0.1:8000/intercept"
    body = call_kwargs[1]["json"]
    assert body["agent_id"] == "test-agent"
    assert body["output_text"] == "answer: ping"
    assert body["metadata"]["function"] == "greet"


@patch("pulse_sdk.httpx.Client")
def test_intercept_manual(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    mock_client.post.return_value = _ok_response("unchanged output")
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent")
    result = guard.intercept("user input", "unchanged output")

    assert result == "unchanged output"
    mock_client.post.assert_called_once_with(
        "http://127.0.0.1:8000/intercept",
        json={
            "agent_id": "test-agent",
            "session_id": None,
            "input_text": "user input",
            "output_text": "unchanged output",
            "metadata": {},
        },
        headers={"x-agent-id": "test-agent"},
    )



@patch("pulse_sdk.httpx.Client")
def test_intercept_sends_org_api_key(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    mock_client.post.return_value = _ok_response("unchanged output")
    mock_client_cls.return_value = mock_client

    guard = PulseGuard(
        "http://127.0.0.1:8000", agent_id="test-agent", api_key="pulse_test_key"
    )
    guard.intercept("user input", "unchanged output")

    assert mock_client.post.call_args.kwargs["headers"] == {
        "x-agent-id": "test-agent",
        "x-api-key": "pulse_test_key",
    }

def test_new_session() -> None:
    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent")
    session_id = guard.new_session()

    assert isinstance(session_id, str)
    parsed = uuid.UUID(session_id)
    assert str(parsed) == session_id
    assert guard._session_id == session_id


@patch("pulse_sdk.httpx.Client")
def test_get_status(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    status_payload = {"status": "ok"}
    response = MagicMock(spec=httpx.Response)
    response.json.return_value = status_payload
    response.raise_for_status = MagicMock()
    mock_client.get.return_value = response
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent")
    result = guard.get_status()

    assert result == status_payload
    mock_client.get.assert_called_once_with("http://127.0.0.1:8000/health")
    response.raise_for_status.assert_called_once()


@patch("pulse_sdk.httpx.Client")
def test_fail_open(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    mock_client.post.side_effect = httpx.ConnectError("connection refused")
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent", fail_open=True)
    result = guard.intercept("in", "safe output")

    assert result == "safe output"


def test_fail_closed_is_default() -> None:
    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent")
    assert guard.fail_open is False


@patch("pulse_sdk.httpx.Client")
def test_intercept_raw_raises_on_unexpected_http_error(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    response = MagicMock(spec=httpx.Response)
    response.status_code = 401
    response.headers = {}
    response.text = "Unauthorized"
    response.json.return_value = {"detail": "Invalid organization key"}
    response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Unauthorized", request=MagicMock(), response=response
    )
    mock_client.post.return_value = response
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent")
    with pytest.raises(httpx.HTTPStatusError):
        guard.intercept_raw("in", "out")


@patch("pulse_sdk.httpx.Client")
def test_circuit_trip(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    response = MagicMock(spec=httpx.Response)
    response.status_code = 409
    response.headers = {}
    response.text = ""
    response.json.return_value = {
        "detail": {"reason": "Circuit breaker tripped", "state": "open"},
    }
    mock_client.post.return_value = response
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent", fail_open=True)

    with pytest.raises(PulseCircuitTrippedException) as exc_info:
        guard.intercept("in", "out")

    assert exc_info.value.status_code == 409
    assert "Circuit breaker tripped" in str(exc_info.value)


@patch("pulse_sdk.httpx.Client")
def test_isolated_agent_423_is_always_blocked(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    response = MagicMock(spec=httpx.Response)
    response.status_code = 423
    response.headers = {}
    response.content = b'{"detail":{"error":"Agent is isolated"}}'
    response.json.return_value = {"detail": {"error": "Agent is isolated"}}
    mock_client.post.return_value = response
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent", fail_open=True)
    with pytest.raises(PulseCircuitTrippedException) as exc_info:
        guard.intercept("in", "out")
    assert exc_info.value.status_code == 423


@patch("pulse_sdk.httpx.Client")
def test_intercept_raw_raises_for_isolated_agent(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    response = MagicMock(spec=httpx.Response)
    response.status_code = 423
    response.headers = {}
    response.content = b'{"detail":{"error":"Agent is isolated"}}'
    response.json.return_value = {"detail": {"error": "Agent is isolated"}}
    mock_client.post.return_value = response
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent", fail_open=True)
    with pytest.raises(PulseCircuitTrippedException) as exc_info:
        guard.intercept_raw("in", "out")
    assert exc_info.value.status_code == 423


# ── Phase 6 Stage 4 tests ───────────────────────────────────────────────────

def test_pulse_result_stable() -> None:
    raw = {
        "ok": True,
        "allowed": True,
        "output_text": "safe response",
        "threat_classification": {
            "threat_level": "LOW",
            "fired_threats": [],
        },
        "policy_violations": [],
    }
    result = PulseResult(raw)

    assert result.allowed is True
    assert result.blocked is False
    assert result.threat_level == "LOW"
    assert result.fired_threats == []
    assert result.policy_violations == []


def test_pulse_result_critical() -> None:
    raw = {
        "ok": False,
        "allowed": False,
        "output_text": "",
        "threat_classification": {
            "threat_level": "CRITICAL",
            "fired_threats": ["data_exfiltration", "policy_bypass"],
        },
        "policy_violations": [
            {"policy_id": "no-pii-export", "matched_text": "customer_id=123"}
        ],
    }
    result = PulseResult(raw)

    assert result.allowed is False
    assert result.blocked is True
    assert result.threat_level == "CRITICAL"
    assert "data_exfiltration" in result.fired_threats
    assert len(result.policy_violations) == 1


def test_governance_exception_message() -> None:
    raw = {
        "allowed": False,
        "threat_classification": {
            "threat_level": "CRITICAL",
            "fired_threats": ["data_exfiltration"],
        },
        "policy_violations": [{"policy_id": "no-pii-export"}],
    }
    result = PulseResult(raw)
    exc = GovernanceException(result)

    assert "CRITICAL" in str(exc)
    assert "data_exfiltration" in str(exc)
    assert "no-pii-export" in str(exc)


@patch("pulse_sdk.httpx.Client")
def test_intercept_raw_returns_pulse_result(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.headers = {}
    response.json.return_value = {
        "ok": True,
        "allowed": True,
        "output_text": "clean response",
        "threat_classification": {
            "threat_level": "LOW",
            "fired_threats": [],
        },
        "policy_violations": [],
    }
    mock_client.post.return_value = response
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent")
    guard.new_session()
    result = guard.intercept_raw("user input", "clean response")

    assert isinstance(result, PulseResult)
    assert result.allowed is True
    assert result.threat_level == "LOW"


@patch("pulse_sdk.httpx.Client")
def test_intercept_raw_fail_open(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    mock_client.post.side_effect = httpx.ConnectError("timeout")
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent", fail_open=True)
    guard.new_session()
    result = guard.intercept_raw("input", "output")

    assert isinstance(result, PulseResult)
    assert result.allowed is True


@patch("pulse_sdk.httpx.Client")
def test_governance_exception_raised_on_critical(mock_client_cls: MagicMock) -> None:
    mock_client = _mock_client()
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.headers = {}
    response.json.return_value = {
        "ok": False,
        "allowed": False,
        "threat_classification": {
            "threat_level": "CRITICAL",
            "fired_threats": ["data_exfiltration"],
        },
        "policy_violations": [{"policy_id": "no-pii-export"}],
    }
    mock_client.post.return_value = response
    mock_client_cls.return_value = mock_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="test-agent")
    guard.new_session()
    result = guard.intercept_raw("leak customer_id", "sending to external endpoint")

    # Developer pattern: raise GovernanceException on critical
    with pytest.raises(GovernanceException) as exc_info:
        if result.threat_level == "CRITICAL" or result.policy_violations:
            raise GovernanceException(result)

    assert exc_info.value.result.threat_level == "CRITICAL"

