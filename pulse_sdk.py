"""
Pulse SDK — governance guard for agent functions.

Usage:
    guard = PulseGuard("http://127.0.0.1:8000", agent_id="my-agent")
    guard.new_session()

    @guard.watch()
    def my_tool(query: str) -> str:
        return f"answer: {query}"

    guard.intercept("user input", "model output", metadata={"step": 1})
    print(guard.get_status())

Phase 6 Stage 4 — PulseResult helper:
    raw = guard.intercept_raw("user input", "model output")
    result = PulseResult(raw)

    if result.threat_level == "CRITICAL" or result.policy_violations:
        raise GovernanceException(result)
"""

from __future__ import annotations

import functools
import json
import logging
import uuid
from typing import Any, Callable, Dict, Optional, TypeVar

import httpx

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

CIRCUIT_TRIP_STATUS_CODES = frozenset({409, 423, 503})


class PulseCircuitTrippedException(Exception):
    """Raised when the Pulse backend circuit breaker blocks the request."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 409,
        detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


class PulseGuard:
    def __init__(self, base_url: str, agent_id: str, fail_open: bool = False, api_key: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.fail_open = fail_open
        self.api_key = api_key
        self._session_id: Optional[str] = None
        self._client = httpx.Client(timeout=30.0)

    def _request_headers(self) -> Dict[str, str]:
        headers = {"x-agent-id": self.agent_id}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    def new_session(self) -> str:
        self._session_id = str(uuid.uuid4())
        return self._session_id

    def get_status(self) -> Dict[str, Any]:
        response = self._client.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()

    def intercept(
        self,
        input_text: str,
        output_text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Send input/output to POST /intercept for governance review.

        Returns output_text unchanged when allowed (or when fail_open and backend is down).
        Raises PulseCircuitTrippedException when the circuit breaker blocks the call.
        """
        meta = dict(metadata or {})
        body: Dict[str, Any] = {
            "agent_id": self.agent_id,
            "session_id": self._session_id,
            "input_text": input_text,
            "output_text": output_text,
            "metadata": meta,
        }
        if meta.get("bdi_score") is not None:
            body["bdi_score"] = meta["bdi_score"]
        if meta.get("entropy") is not None:
            body["entropy"] = meta["entropy"]

        try:
            response = self._client.post(
                f"{self.base_url}/intercept",
                json=body,
                headers=self._request_headers(),
            )
        except httpx.HTTPError as exc:
            if self.fail_open:
                logger.warning("Pulse backend unreachable (%s); fail_open=True, passing through.", exc)
                return output_text
            raise

        if self._is_circuit_trip(response):
            detail = self._response_detail(response)
            reason = detail if isinstance(detail, str) else detail.get("reason", "Circuit breaker tripped")
            raise PulseCircuitTrippedException(
                str(reason),
                status_code=response.status_code,
                detail=detail,
            )

        if response.status_code >= 400:
            if self.fail_open:
                logger.warning(
                    "Pulse intercept returned HTTP %s; fail_open=True, passing through.",
                    response.status_code,
                )
                return output_text
            response.raise_for_status()

        try:
            payload = response.json()
        except json.JSONDecodeError:
            return output_text

        return str(payload.get("output_text", output_text))

    def intercept_raw(
        self,
        input_text: str,
        output_text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "PulseResult":
        """
        Like intercept() but returns a PulseResult instead of a plain string.
        Use this when you want to inspect threat_level or policy_violations.

        Example:
            result = guard.intercept_raw(input_text, output_text)
            if result.threat_level == "CRITICAL" or result.policy_violations:
                raise GovernanceException(result)
        """
        meta = dict(metadata or {})
        body: Dict[str, Any] = {
            "agent_id": self.agent_id,
            "session_id": self._session_id,
            "input_text": input_text,
            "output_text": output_text,
            "metadata": meta,
        }

        try:
            response = self._client.post(
                f"{self.base_url}/intercept",
                json=body,
                headers=self._request_headers(),
            )
        except httpx.HTTPError as exc:
            if self.fail_open:
                logger.warning("Pulse backend unreachable (%s); fail_open=True, passing through.", exc)
                return PulseResult({"ok": True, "allowed": True, "output_text": output_text})
            raise

        if self._is_circuit_trip(response):
            detail = self._response_detail(response)
            reason = detail if isinstance(detail, str) else detail.get("reason", "Circuit breaker tripped")
            raise PulseCircuitTrippedException(
                str(reason),
                status_code=response.status_code,
                detail=detail,
            )

        if response.status_code >= 400:
            if self.fail_open:
                logger.warning(
                    "Pulse intercept returned HTTP %s; fail_open=True, passing through.",
                    response.status_code,
                )
                return PulseResult({"ok": True, "allowed": True, "output_text": output_text})
            response.raise_for_status()

        try:
            payload = response.json()
        except json.JSONDecodeError:
            return PulseResult({"ok": True, "allowed": True, "output_text": output_text})

        return PulseResult(payload)

    def watch(self, fn: Optional[F] = None, *, metadata: Optional[Dict[str, Any]] = None) -> F | Callable[[F], F]:
        """Decorator that runs intercept() after the wrapped function completes."""

        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                result = func(*args, **kwargs)
                input_text = self._serialize_input(args, kwargs)
                output_text = self._serialize_output(result)
                call_meta = {**(metadata or {}), "function": func.__name__}
                self.intercept(input_text, output_text, metadata=call_meta)
                return result

            return wrapper  # type: ignore[return-value]

        if fn is not None:
            return decorator(fn)
        return decorator

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "PulseGuard":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @staticmethod
    def _is_circuit_trip(response: httpx.Response) -> bool:
        if response.status_code not in CIRCUIT_TRIP_STATUS_CODES:
            return False
        if response.headers.get("x-request-dropped") == "1":
            return True
        # Isolation is a hard governance block even when FastAPI returns its
        # usual JSON error body. Never fail open on HTTP 423.
        if response.status_code in {409, 423}:
            return True
        if response.status_code == 503 and not response.content:
            return True
        return False

    @staticmethod
    def _response_detail(response: httpx.Response) -> Any:
        try:
            body = response.json()
            return body.get("detail", body)
        except json.JSONDecodeError:
            return response.text or f"HTTP {response.status_code}"

    @staticmethod
    def _serialize_input(args: tuple[Any, ...], kwargs: Dict[str, Any]) -> str:
        parts = [repr(arg) for arg in args]
        parts.extend(f"{key}={value!r}" for key, value in kwargs.items())
        return ", ".join(parts)

    @staticmethod
    def _serialize_output(result: Any) -> str:
        if isinstance(result, str):
            return result
        try:
            return json.dumps(result)
        except TypeError:
            return repr(result)


# ── Phase 6 Stage 4: PulseResult & GovernanceException ──

class PulseResult:
    """
    Wraps a Pulse /intercept response for easy governance enforcement.

    Attributes:
        threat_level      — "LOW", "MEDIUM", "HIGH", or "CRITICAL"
        fired_threats     — list of threat class names that fired
        policy_violations — list of org policy violations (may be empty)
        allowed           — True if the request was allowed through
        blocked           — True if the circuit breaker tripped
    """

    def __init__(self, raw: dict) -> None:
        self._raw = raw
        tc = raw.get("threat_classification") or {}
        self.threat_level: str = tc.get("threat_level", "LOW")
        self.fired_threats: list = tc.get("fired_threats") or []
        self.policy_violations: list = raw.get("policy_violations") or []
        self.allowed: bool = raw.get("allowed", True)
        self.blocked: bool = not self.allowed

    def __repr__(self) -> str:
        return (
            f"PulseResult(threat_level={self.threat_level!r}, "
            f"fired_threats={self.fired_threats}, "
            f"policy_violations={len(self.policy_violations)} violation(s), "
            f"allowed={self.allowed})"
        )


class GovernanceException(Exception):
    """Raised when a Pulse governance check fails."""

    def __init__(self, result: PulseResult) -> None:
        self.result = result
        details = []
        if result.threat_level in ("CRITICAL", "HIGH"):
            details.append(f"threat_level={result.threat_level}")
        if result.fired_threats:
            details.append(f"fired_threats={result.fired_threats}")
        if result.policy_violations:
            ids = [v.get("policy_id", "?") for v in result.policy_violations]
            details.append(f"policy_violations={ids}")
        super().__init__("Pulse governance check failed: " + ", ".join(details))

