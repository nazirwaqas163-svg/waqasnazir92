import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from dataclasses import asdict
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Union

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from audit import supabase_audit_client
from baseline import baseline_reply, extract_text
from bdi import BDIState
from circuit_breaker import CircuitBreakerMiddleware, RequestAction
from embeddings import embed_texts, novelty_score
from compliance_report import compliance_store
from policy_engine import PolicyEvaluation, evaluate_tool_call
from pulse_feed import PulseEvent, PulseFeed
from session_store import session_store
from refusal import detect_refusal
from synthesis_engine import forensic_auditor, synthesis_runner
from drift import drift_engine
APP_NAME = "pulse-proxy"
SYNTHESIS_ENABLED = os.getenv("PULSE_SYNTHESIS_ENABLED", "true").lower() in {"1", "true", "yes"}
SHADOW_MODE = os.getenv("PULSE_SHADOW_MODE", "false").lower() in {"1", "true", "yes"}
UPSTREAM_CHAT_URL = os.getenv("PULSE_UPSTREAM_CHAT_URL", "https://api.openai.com/v1/chat/completions")
UPSTREAM_API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("PULSE_UPSTREAM_API_KEY")
UPSTREAM_TIMEOUT = float(os.getenv("PULSE_UPSTREAM_TIMEOUT", "120"))
AGENT_COOLDOWN_SECONDS = float(os.getenv("PULSE_AGENT_COOLDOWN_SECONDS", "30"))
FINANCIAL_TRANSACTION_LIMIT = Decimal("5000")
FINANCIAL_KEYWORDS = {
    "budget",
    "charge",
    "contract",
    "cost",
    "expense",
    "financial",
    "invoice",
    "order",
    "pay",
    "payment",
    "procure",
    "procurement",
    "purchase",
    "quote",
    "requisition",
    "spend",
    "transaction",
    "vendor",
}
FINANCIAL_FIELD_HINTS = {
    "amount",
    "budget",
    "charge",
    "cost",
    "expense",
    "invoice",
    "payment",
    "price",
    "purchase",
    "quote",
    "spend",
    "total",
    "transaction",
    "value",
}
AMOUNT_PATTERN = re.compile(
    r"(?:\$|usd\s*)\s*(\d[\d,]*(?:\.\d+)?)|(\d[\d,]*(?:\.\d+)?)\s*(?:usd|dollars?)",
    re.IGNORECASE,
)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    if SYNTHESIS_ENABLED:
        synthesis_runner.start()
    yield
    if SYNTHESIS_ENABLED:
        synthesis_runner.stop()


app = FastAPI(title=APP_NAME, version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

feed = PulseFeed(max_events=int(os.getenv("PULSE_FEED_LIMIT", "500")))
bdi_state = BDIState()
circuit_breaker = CircuitBreakerMiddleware(agent_cooldown_seconds=AGENT_COOLDOWN_SECONDS)


def _emit_circuit_breaker_event(event: object) -> None:
    if not hasattr(event, "state"):
        return

    state = getattr(event, "state", None)
    state_value = state.value if hasattr(state, "value") else str(state or "unknown")
    decision = "blocked" if state_value in {"open", "half-open"} else "allowed"
    status_code = 200 if decision == "allowed" else 503

    feed.add(
        PulseEvent(
            kind="governance",
            text="kill-switch",
            data={
                "decision": decision,
                "status_code": status_code,
                "state": state_value,
                "reason": getattr(event, "reason", "unknown"),
                "bdi_score": getattr(event, "bdi_score", 0.0),
                "entropy": getattr(event, "entropy", 0.0),
                "timestamp": getattr(event, "timestamp", ""),
            },
        )
    )


circuit_breaker.register_listener(_emit_circuit_breaker_event)


class ChatProxyRequest(BaseModel):
    model: str = Field(default="gpt-4o-mini")
    messages: List[Dict[str, Any]] = Field(default_factory=list)
    temperature: Optional[float] = None
    stream: bool = False
    bdi_score: Optional[float] = None
    entropy: Optional[float] = None

    class Config:
        extra = "allow"


class PulseToolCallRequest(BaseModel):
    operation: str
    agent_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class CircuitBreakerOpenRequest(BaseModel):
    reason: str = Field(default="Manual kill switch activated from dashboard")
    bdi_score: float = Field(default=1.0, ge=0.0, le=1.0)
    entropy: float = Field(default=0.0, ge=0.0, le=1.0)


class CircuitBreakerCloseRequest(BaseModel):
    reason: str = Field(default="Manual reset from dashboard")
    bdi_score: float = Field(default=0.0, ge=0.0, le=1.0)
    entropy: float = Field(default=0.0, ge=0.0, le=1.0)


class InterceptRequest(BaseModel):
    agent_id: str
    session_id: Optional[str] = None
    input_text: str = ""
    output_text: str = ""
    metadata: Optional[Dict[str, Any]] = None
    bdi_score: Optional[float] = None
    entropy: Optional[float] = None


def _dropped_response(disposition: Dict[str, Any]) -> Response:
    """
    Explicitly drop the request without a retryable 409 Conflict.

    Empty 503 + Connection: close signals the proxy rejected the call;
    agents should not treat this as a conflict/retry loop trigger.
    """
    retry_after = str(int(max(1, disposition.get("cooldown_seconds_remaining", 30))))
    return Response(
        status_code=503,
        content=b"",
        media_type=None,
        headers={
            "Connection": "close",
            "X-Request-Dropped": "1",
            "X-Circuit-Breaker": str(disposition.get("state", "open")),
            "X-Request-Action": str(disposition.get("action", RequestAction.DROP.value)),
            "Retry-After": retry_after,
        },
    )


def _record_shadow_event(
    disposition: Dict[str, Any],
    *,
    agent_id: Optional[str],
    bdi_score: float,
    entropy: float,
) -> None:
    feed.add(
        PulseEvent(
            kind="shadow",
            text="would-block",
            data={
                "decision": "shadow_allowed",
                "status_code": 200,
                "shadow_mode": True,
                "would_have_action": disposition.get("would_have_action"),
                "would_have_reason": disposition.get("would_have_reason"),
                "agent_id": agent_id,
                "bdi_score": bdi_score,
                "entropy": entropy,
            },
        )
    )


def _record_drop_event(disposition: Dict[str, Any], *, agent_id: Optional[str], bdi_score: float, entropy: float) -> None:
    feed.add(
        PulseEvent(
            kind="governance",
            text="request-dropped",
            data={
                "decision": "dropped",
                "status_code": 503,
                "action": disposition.get("action"),
                "reason": disposition.get("reason"),
                "state": disposition.get("state"),
                "agent_id": agent_id,
                "bdi_score": bdi_score,
                "entropy": entropy,
                "cooldown_active": disposition.get("cooldown_active", False),
                "cooldown_seconds_remaining": disposition.get("cooldown_seconds_remaining", 0),
            },
        )
    )


def _auth_headers(request: Request) -> Dict[str, str]:
    headers = {"content-type": "application/json"}
    incoming_auth = request.headers.get("authorization")
    if incoming_auth:
        headers["authorization"] = incoming_auth
    elif UPSTREAM_API_KEY:
        headers["authorization"] = f"Bearer {UPSTREAM_API_KEY}"
    return headers


def _messages_text(messages: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for message in messages:
        role = message.get("role", "unknown")
        parts.append(f"{role}: {extract_text(message.get('content', ''))}")
    return "\n".join(parts).strip()


def _to_decimal(value: Any) -> Optional[Decimal]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float, Decimal)):
        return Decimal(str(value))
    if isinstance(value, str):
        normalized = value.replace(",", "").strip()
        if not normalized:
            return None
        try:
            return Decimal(normalized)
        except InvalidOperation:
            return None
    return None


def _financial_amounts_from_payload(value: Any, key_path: str = "") -> List[Decimal]:
    amounts: List[Decimal] = []
    lowered_key = key_path.lower()
    has_financial_hint = any(hint in lowered_key for hint in FINANCIAL_FIELD_HINTS)

    if isinstance(value, dict):
        for key, item in value.items():
            next_key = f"{key_path}.{key}" if key_path else str(key)
            amounts.extend(_financial_amounts_from_payload(item, next_key))
    elif isinstance(value, list):
        for item in value:
            amounts.extend(_financial_amounts_from_payload(item, key_path))
    elif has_financial_hint:
        amount = _to_decimal(value)
        if amount is not None:
            amounts.append(amount)

    return amounts


def _financial_amounts_from_text(text: str) -> List[Decimal]:
    amounts: List[Decimal] = []
    for match in AMOUNT_PATTERN.finditer(text):
        raw_amount = match.group(1) or match.group(2)
        amount = _to_decimal(raw_amount)
        if amount is not None:
            amounts.append(amount)
    return amounts


def _is_financial_text(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in FINANCIAL_KEYWORDS)


def _calculate_shannon_entropy(text: str) -> float:
    text = text or ""
    if not text:
        return 0.0
    frequencies: dict[str, int] = {}
    for symbol in text:
        frequencies[symbol] = frequencies.get(symbol, 0) + 1

    entropy = 0.0
    length = len(text)
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * (probability and __import__("math").log2(probability))

    max_entropy = __import__("math").log2(len(frequencies)) if frequencies else 1.0
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
    return min(1.0, max(0.0, normalized_entropy))


def _normalized_bdi_score(bdi_snapshot: dict[str, object]) -> float:
    beliefs = bdi_snapshot.get("beliefs") or {}
    desires = bdi_snapshot.get("desires") or []
    intentions = bdi_snapshot.get("intentions") or []
    turns = int(bdi_snapshot.get("turns") or 0)

    public_beliefs = {k: v for k, v in beliefs.items() if not k.startswith("_")}

    belief_score = min(1.0, len(public_beliefs) / 8.0)
    desire_score = min(1.0, len(desires) / 8.0)
    intention_score = min(1.0, len(intentions) / 5.0)
    turn_score = min(1.0, turns / 20.0)

    escalation = int(beliefs.get("escalation_keywords") or 0)
    escalation_bonus = min(0.4, escalation * 0.1)

    score = (
        (belief_score * 0.25)
        + (desire_score * 0.25)
        + (intention_score * 0.30)
        + (turn_score * 0.20)
        + escalation_bonus
    )
    return min(1.0, max(0.0, score))


def _should_block_financial_transaction(payload: ChatProxyRequest) -> bool:
    payload_dict = payload.model_dump(exclude_none=True)
    prompt_text = _messages_text(payload.messages)
    amounts = _financial_amounts_from_payload(payload_dict)

    if _is_financial_text(prompt_text):
        amounts.extend(_financial_amounts_from_text(prompt_text))

    return any(amount > FINANCIAL_TRANSACTION_LIMIT for amount in amounts)


def _enforce_financial_circuit_breaker(payload: ChatProxyRequest) -> None:
    if _should_block_financial_transaction(payload):
        raise HTTPException(
            status_code=403,
            detail="Forbidden: financial transactions over $5,000 are blocked by the governance circuit breaker.",
        )


def _record_input(payload: ChatProxyRequest) -> Dict[str, Any]:
    prompt_text = _messages_text(payload.messages)
    vectors = embed_texts([prompt_text]) if prompt_text else []
    novelty = novelty_score(prompt_text, feed.recent_texts(limit=25)) if prompt_text else 0.0
    bdi = bdi_state.observe(payload.messages)
    bdi_score = _normalized_bdi_score(bdi)
    pulse = {
        "request_id": str(uuid.uuid4()),
        "model": payload.model,
        "prompt_chars": len(prompt_text),
        "embedding_dim": len(vectors[0]) if vectors else 0,
        "novelty": novelty,
        "bdi": bdi,
        "bdi_score": bdi_score,
        "decision": "allowed",
        "status_code": 200,
    }
    feed.add(PulseEvent(kind="input", text=prompt_text, data=pulse))
    return pulse


def _record_output(request_id: str, response_json: Dict[str, Any]) -> None:
    text = ""
    choices = response_json.get("choices") or []
    if choices:
        message = choices[0].get("message") or {}
        text = extract_text(message.get("content", ""))
    refusal = detect_refusal(text)
    feed.add(
        PulseEvent(
            kind="output",
            text=text,
            data={
                "request_id": request_id,
                "refusal": refusal,
                "response_chars": len(text),
                "decision": "allowed",
                "status_code": 200,
            },
        )
    )


def _extra_payload_fields(payload: ChatProxyRequest) -> Dict[str, Any]:
    return getattr(payload, "model_extra", None) or {}


def _agent_id(payload: ChatProxyRequest, request: Request) -> Optional[str]:
    extra_fields = _extra_payload_fields(payload)
    value = extra_fields.get("agent_id") or request.headers.get("x-agent-id")
    return str(value) if value is not None else None


def _payload_override(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _effective_bdi_score(payload: ChatProxyRequest, pulse: Dict[str, Any]) -> float:
    override = _payload_override(payload.bdi_score)
    if override is not None:
        return override
    extra_fields = _extra_payload_fields(payload)
    override = _payload_override(extra_fields.get("bdi_score"))
    if override is not None:
        return override
    return float(pulse.get("bdi_score") or 0.0)


def _effective_entropy(payload: ChatProxyRequest, prompt_text: str) -> float:
    override = _payload_override(payload.entropy)
    if override is not None:
        return override
    extra_fields = _extra_payload_fields(payload)
    override = _payload_override(extra_fields.get("entropy"))
    if override is not None:
        return override
    return _calculate_shannon_entropy(prompt_text)


def _enforce_policy(operation: str | None, agent_id: Optional[str] = None) -> PolicyEvaluation:
    evaluation = evaluate_tool_call(operation)
    policy_data = evaluation.to_dict()
    policy_data["decision"] = "allowed" if evaluation.allowed else "blocked"
    policy_data["status_code"] = 200 if evaluation.allowed else 403
    if not evaluation.allowed:
        policy_data["shadow_mode"] = SHADOW_MODE
        compliance_store.record_blocked(policy_data, agent_id=agent_id)
    feed.add(
        PulseEvent(
            kind="policy",
            text=operation or "",
            data=policy_data,
        )
    )
    if not evaluation.allowed:
        if SHADOW_MODE:
            return evaluation
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Policy evaluation denied request",
                "policy": evaluation.to_dict(),
            },
        )
    return evaluation


def _session_id_from_payload(payload: ChatProxyRequest) -> Optional[str]:
    extra_fields = _extra_payload_fields(payload)
    value = extra_fields.get("session_id")
    return str(value) if value is not None else None


def _request_action(payload: ChatProxyRequest, request: Request) -> str:
    extra_fields = _extra_payload_fields(payload)
    if extra_fields.get("operation") is not None:
        return str(extra_fields["operation"])
    return request.url.path


def _extract_output_text(response_payload: Dict[str, Any]) -> str:
    if response_payload.get("dropped"):
        return ""
    choices = response_payload.get("choices") or []
    if choices:
        message = choices[0].get("message") or {}
        return extract_text(message.get("content", ""))
    if response_payload.get("error") is not None:
        return str(response_payload["error"])
    if response_payload.get("detail") is not None:
        return str(response_payload["detail"])
    return ""


def _policy_result(response_payload: Dict[str, Any]) -> str:
    status_code = response_payload.get("status_code", 200)
    if response_payload.get("dropped") or status_code >= 400:
        return "blocked"
    return "allowed"


async def _insert_ai_event_log(
    *,
    event_id: str,
    agent_id: Optional[str],
    action: str,
    input_text: str,
    output_text: str,
    bdi_score: Optional[float],
    policy_result: str,
    session_id: Optional[str] = None,
) -> None:
    await supabase_audit_client.insert_ai_event(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        action=action,
        input_text=input_text,
        output_text=output_text,
        bdi_score=bdi_score,
        policy_result=policy_result,
        session_id=session_id,
    )


async def _insert_audit_log(
    payload: ChatProxyRequest,
    request: Request,
    pulse: Dict[str, Any],
    response_payload: Dict[str, Any],
) -> None:
    agent_id = _agent_id(payload, request)
    bdi_score = _effective_bdi_score(payload, pulse)
    event_id = await supabase_audit_client.insert_audit_log(
        agent_id=agent_id,
        request_payload=payload.model_dump(exclude_none=True),
        response_payload=response_payload,
        bdi_score=bdi_score,
    )
    await _insert_ai_event_log(
        event_id=event_id,
        agent_id=agent_id,
        action=_request_action(payload, request),
        input_text=_messages_text(payload.messages),
        output_text=_extract_output_text(response_payload),
        bdi_score=bdi_score,
        policy_result=_policy_result(response_payload),
        session_id=_session_id_from_payload(payload),
    )


async def _insert_intercept_logs(
    payload: InterceptRequest,
    *,
    request_id: str,
    bdi_score: float,
    policy_result: str,
) -> None:
    action = str((payload.metadata or {}).get("operation") or "/intercept")
    event_id = await supabase_audit_client.insert_audit_log(
        agent_id=payload.agent_id,
        request_payload=payload.model_dump(exclude_none=True),
        response_payload={
            "request_id": request_id,
            "output_text": payload.output_text,
            "policy_result": policy_result,
        },
        bdi_score=bdi_score,
        event_id=request_id,
    )
    await _insert_ai_event_log(
        event_id=event_id,
        agent_id=payload.agent_id,
        action=action,
        input_text=payload.input_text,
        output_text=payload.output_text,
        bdi_score=bdi_score,
        policy_result=policy_result,
        session_id=payload.session_id,
    )


def _fallback_completion(payload: ChatProxyRequest, pulse: Dict[str, Any]) -> Dict[str, Any]:
    content = baseline_reply(payload.messages)
    now = int(time.time())
    response = {
        "id": f"chatcmpl-pulse-{pulse['request_id']}",
        "object": "chat.completion",
        "created": now,
        "model": payload.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "pulse": {**pulse, "mode": "baseline"},
    }
    _record_output(pulse["request_id"], response)
    return response


def _gate_or_drop(
    payload: ChatProxyRequest,
    request: Request,
    *,
    bdi_score: float,
    entropy: float,
) -> Optional[Response]:
    agent_id = _agent_id(payload, request)
    disposition = circuit_breaker.gate_request(
        agent_id=agent_id,
        bdi_score=bdi_score,
        entropy=entropy,
        shadow_mode=SHADOW_MODE,
    )
    action = disposition.get("action")

    if disposition.get("shadow_mode") and disposition.get("would_have_action"):
        _record_shadow_event(disposition, agent_id=agent_id, bdi_score=bdi_score, entropy=entropy)
        return None

    if action in {RequestAction.DROP.value, RequestAction.TRIP_DROP.value}:
        _record_drop_event(disposition, agent_id=agent_id, bdi_score=bdi_score, entropy=entropy)
        return _dropped_response(disposition)

    return None


@app.get("/health")
def health() -> Dict[str, Any]:
    cb_snapshot = circuit_breaker.status()
    return {
        "ok": True,
        "service": APP_NAME,
        "shadow_mode": SHADOW_MODE,
        "synthesis_enabled": SYNTHESIS_ENABLED,
        "upstream_configured": bool(UPSTREAM_API_KEY),
        "events": feed.count,
        "circuit_breaker": {
            "state": cb_snapshot["state"],
            "allows_requests": cb_snapshot["allows_requests"],
            "last_event": circuit_breaker.last_event.to_dict() if circuit_breaker.last_event is not None else None,
        },
    }


@app.get("/circuit-breaker/status")
def circuit_breaker_status() -> dict[str, object]:
    return circuit_breaker.status()


@app.post("/circuit-breaker/open")
def circuit_breaker_open(payload: CircuitBreakerOpenRequest) -> dict[str, object]:
    circuit_breaker.open(
        reason=payload.reason,
        bdi_score=payload.bdi_score,
        entropy=payload.entropy,
    )
    if circuit_breaker.last_failure is not None:
        circuit_breaker.last_failure["manual"] = True
    return {
        "ok": True,
        "message": "Circuit breaker manually opened",
        "status_code": 503,
        **circuit_breaker.status(),
    }


@app.post("/circuit-breaker/close")
def circuit_breaker_close(payload: CircuitBreakerCloseRequest) -> dict[str, object]:
    circuit_breaker.close(
        reason=payload.reason,
        bdi_score=payload.bdi_score,
        entropy=payload.entropy,
    )
    return {
        "ok": True,
        "message": "Circuit breaker reset to closed",
        "status_code": 200,
        **circuit_breaker.status(),
    }


@app.get("/pulse")
def pulse(limit: int = 50) -> Dict[str, Any]:
    return {"events": feed.list(limit=limit)}


@app.post("/pulse")
def pulse_tool_call(payload: PulseToolCallRequest, request: Request):
    disposition = circuit_breaker.gate_request(
        agent_id=payload.agent_id or request.headers.get("x-agent-id"),
        bdi_score=0.0,
        entropy=0.0,
        shadow_mode=SHADOW_MODE,
    )
    if disposition.get("shadow_mode") and disposition.get("would_have_action"):
        _record_shadow_event(disposition, agent_id=payload.agent_id, bdi_score=0.0, entropy=0.0)
    elif disposition.get("action") != RequestAction.PROCEED.value:
        _record_drop_event(
            disposition,
            agent_id=payload.agent_id,
            bdi_score=0.0,
            entropy=0.0,
        )
        return _dropped_response(disposition)

    evaluation = _enforce_policy(payload.operation, agent_id=payload.agent_id)
    event = PulseEvent(
        kind="tool_call",
        text=payload.operation,
        data={
            "decision": "allowed",
            "status_code": 200,
            "agent_id": payload.agent_id,
            "metadata": payload.metadata or {},
            "policy": evaluation.to_dict(),
        },
    )
    feed.add(event)
    return {"ok": True, "policy": evaluation.to_dict(), "event": asdict(event)}


@app.get("/events")
def events() -> Dict[str, Any]:
    return {"events": feed.list(limit=50)}


@app.get("/pulse/bdi")
def pulse_bdi() -> Dict[str, Any]:
    return bdi_state.snapshot()


@app.post("/v1/chat/completions")
async def chat_completions(payload: ChatProxyRequest, request: Request):
    extra_fields = _extra_payload_fields(payload)
    if extra_fields.get("operation") is not None:
        _enforce_policy(str(extra_fields["operation"]), agent_id=_agent_id(payload, request))

    _enforce_financial_circuit_breaker(payload)

    prompt_text = _messages_text(payload.messages)
    entropy = _effective_entropy(payload, prompt_text)
    provisional_pulse: Dict[str, Any] = {"entropy": entropy, "bdi_score": 0.0}
    bdi_score = _effective_bdi_score(payload, provisional_pulse)

    dropped = _gate_or_drop(payload, request, bdi_score=bdi_score, entropy=entropy)
    if dropped is not None:
        await _insert_audit_log(
            payload,
            request,
            provisional_pulse,
            {"status_code": 503, "dropped": True},
        )
        return dropped

    pulse = _record_input(payload)
    pulse["entropy"] = entropy
    pulse["bdi_score"] = _effective_bdi_score(payload, pulse)

    if not UPSTREAM_API_KEY and not request.headers.get("authorization"):
        response_json = _fallback_completion(payload, pulse)
        await _insert_audit_log(payload, request, pulse, response_json)
        return JSONResponse(response_json)

    body = payload.model_dump(exclude_none=True)
    headers = _auth_headers(request)

    if payload.stream:
        async def stream_upstream():
            response_payload: Dict[str, Any] = {"stream": True, "chunks": 0, "status_code": 200}
            try:
                async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
                    async with client.stream("POST", UPSTREAM_CHAT_URL, headers=headers, json=body) as upstream:
                        response_payload["status_code"] = upstream.status_code
                        if upstream.status_code >= 400:
                            detail = await upstream.aread()
                            response_payload["error"] = detail.decode("utf-8", "ignore")
                            await _insert_audit_log(payload, request, pulse, response_payload)
                            raise HTTPException(status_code=upstream.status_code, detail=response_payload["error"])
                        async for chunk in upstream.aiter_bytes():
                            response_payload["chunks"] += 1
                            yield chunk
            except httpx.HTTPError as exc:
                response_payload["status_code"] = 502
                response_payload["error"] = str(exc)
                await _insert_audit_log(payload, request, pulse, response_payload)
                raise HTTPException(status_code=502, detail=str(exc))
            feed.add(PulseEvent(kind="stream_end", text="", data={"request_id": pulse["request_id"]}))
            await _insert_audit_log(payload, request, pulse, response_payload)

        return StreamingResponse(stream_upstream(), media_type="text/event-stream")

    try:
        async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
            upstream = await client.post(UPSTREAM_CHAT_URL, headers=headers, json=body)
    except httpx.HTTPError as exc:
        await _insert_audit_log(
            payload,
            request,
            pulse,
            {"status_code": 502, "error": str(exc)},
        )
        raise HTTPException(status_code=502, detail=str(exc))

    if upstream.status_code >= 400:
        await _insert_audit_log(
            payload,
            request,
            pulse,
            {"status_code": upstream.status_code, "error": upstream.text},
        )
        raise HTTPException(status_code=upstream.status_code, detail=upstream.text)

    response_json = upstream.json()
    response_json["pulse"] = {**pulse, "mode": "proxy"}
    _record_output(pulse["request_id"], response_json)
    await _insert_audit_log(payload, request, pulse, response_json)
    return JSONResponse(response_json)


@app.post("/intercept")
async def intercept(payload: InterceptRequest) -> Dict[str, Any]:
    """SDK hook: record agent input/output and apply circuit-breaker governance."""
    bdi_score = session_store.record_turn(
        payload.session_id or "default",
        payload.agent_id or "unknown",
        payload.input_text,
        payload.output_text,
    )
    drift_result = drift_engine.record_turn(
        session_id=payload.session_id or "default",
        input_text=payload.input_text,
        output_text=payload.output_text,    
)
    entropy = (
        float(payload.entropy)
        if payload.entropy is not None
        else _calculate_shannon_entropy(payload.input_text)
    )

    disposition = circuit_breaker.gate_request(
        agent_id=payload.agent_id,
        bdi_score=bdi_score,
        entropy=entropy,
        shadow_mode=SHADOW_MODE,
        intercept=True,
    )

    if disposition.get("shadow_mode") and disposition.get("would_have_action"):
        _record_shadow_event(
            disposition,
            agent_id=payload.agent_id,
            bdi_score=bdi_score,
            entropy=entropy,
        )
    elif disposition.get("action") != RequestAction.PROCEED.value:
        _record_drop_event(
            disposition,
            agent_id=payload.agent_id,
            bdi_score=bdi_score,
            entropy=entropy,
        )
        request_id = str(uuid.uuid4())
        await _insert_intercept_logs(
            payload,
            request_id=request_id,
            bdi_score=bdi_score,
            policy_result="blocked",
        )
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Circuit breaker tripped",
                "reason": disposition.get("reason"),
                "state": disposition.get("state"),
                "action": disposition.get("action"),
            },
        )

    request_id = str(uuid.uuid4())
    feed.add(
        PulseEvent(
            kind="input",
            text=payload.input_text,
            data={
                "request_id": request_id,
                "agent_id": payload.agent_id,
                "session_id": payload.session_id,
                "metadata": payload.metadata or {},
                "bdi_score": bdi_score,
                "entropy": entropy,
                "decision": "allowed",
                "status_code": 200,
            },
        )
    )
    refusal = detect_refusal(payload.output_text)
    feed.add(
        PulseEvent(
            kind="output",
            text=payload.output_text,
            data={
                "request_id": request_id,
                "agent_id": payload.agent_id,
                "session_id": payload.session_id,
                "refusal": refusal,
                "decision": "allowed",
                "status_code": 200,
            },
        )
    )
    await _insert_intercept_logs(
        payload,
        request_id=request_id,
        bdi_score=bdi_score,
        policy_result="allowed",
    )
    return {
        "ok": True,
        "allowed": True,
        "output_text": payload.output_text,
        "request_id": request_id,
        "drift": drift_result,
    }


@app.post("/pulse/reset")
def reset() -> Dict[str, Any]:
    feed.clear()
    bdi_state.reset()
    session_store.reset()
    circuit_breaker.close(reason="manual reset", bdi_score=0.0, entropy=0.0)
    return {"ok": True}


@app.get("/synthesis/report")
def synthesis_report() -> Dict[str, Any]:
    """Latest pattern report from the background synthesis engine."""
    report = synthesis_runner.last_report
    if report is None:
        report = forensic_auditor.generate_pattern_report()
    return {"ok": True, "report": report}


@app.post("/synthesis/run")
def synthesis_run_now() -> Dict[str, Any]:
    """Trigger an on-demand synthesis pass (runs off the request thread)."""
    report = synthesis_runner.run_once()
    return {"ok": True, "report": report}


@app.get("/compliance/export", response_model=None)
def compliance_export(format: str = "json") -> Union[Dict[str, Any], Response]:
    """Export tagged compliance events (JSON or markdown)."""
    if format.lower() in {"md", "markdown"}:
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(
            compliance_store.export_markdown(),
            media_type="text/markdown",
        )
    return {"ok": True, "report": compliance_store.export_report()}


@app.get("/compliance/events")
def compliance_events(limit: int = 100) -> Dict[str, Any]:
    return {"ok": True, "events": compliance_store.list_blocked(limit=limit)}
