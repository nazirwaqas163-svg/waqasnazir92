"""Integration-style test: OpenAI-style chat completion guarded by PulseGuard (all mocked)."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import httpx

from pulse_sdk import PulseGuard

OPENAI_RESPONSE: Dict[str, Any] = {
    "id": "chatcmpl-test123",
    "object": "chat.completion",
    "created": 1700000000,
    "model": "gpt-4o-mini",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "The capital of France is Paris."},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
}


def _mock_openai_create(messages: List[Dict[str, str]]) -> Dict[str, Any]:
    """Stand-in for OpenAI client.chat.completions.create()."""
    return OPENAI_RESPONSE


@patch("pulse_sdk.httpx.Client")
def test_openai_chat_wrapped_with_watch(mock_client_cls: MagicMock) -> None:
    pulse_client = MagicMock()
    pulse_response = MagicMock(spec=httpx.Response)
    pulse_response.status_code = 200
    pulse_response.headers = {}
    assistant_text = OPENAI_RESPONSE["choices"][0]["message"]["content"]
    pulse_response.json.return_value = {"ok": True, "output_text": assistant_text}
    pulse_client.post.return_value = pulse_response
    pulse_client.get = MagicMock()
    mock_client_cls.return_value = pulse_client

    guard = PulseGuard("http://127.0.0.1:8000", agent_id="openai-agent")
    guard.new_session()

    with patch("test_openai_agent._mock_openai_create", wraps=_mock_openai_create) as mock_openai:
        @guard.watch(metadata={"provider": "openai"})
        def chat_completion(messages: List[Dict[str, str]]) -> Dict[str, Any]:
            return _mock_openai_create(messages)

        messages = [{"role": "user", "content": "What is the capital of France?"}]
        result = chat_completion(messages)

    mock_openai.assert_called_once_with(messages)
    assert result == OPENAI_RESPONSE
    assert result["choices"][0]["message"]["content"] == "The capital of France is Paris."

    pulse_client.post.assert_called_once()
    intercept_body = pulse_client.post.call_args[1]["json"]
    assert intercept_body["agent_id"] == "openai-agent"
    assert intercept_body["session_id"] == guard._session_id
    assert "What is the capital of France?" in intercept_body["input_text"]
    assert assistant_text in intercept_body["output_text"]
    assert intercept_body["metadata"]["function"] == "chat_completion"
    assert intercept_body["metadata"]["provider"] == "openai"
