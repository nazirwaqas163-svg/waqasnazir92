"""Unit tests for pulse_sdk.PulseGuard — all HTTP mocked, no live calls."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import httpx
import pytest

from pulse_sdk import PulseCircuitTrippedException, PulseGuard


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
