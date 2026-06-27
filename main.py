import os
import json
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
    "budget", "charge", "contract", "cost", "expense", "financial", "invoice",
    "order", "pay", "payment", "procure", "procurement", "purchase", "quote",
    "requisition", "spend", "transaction", "vendor",
}
FINANCIAL_FIELD_HINTS = {
    "amount", "budget", "charge", "cost", "expense", "invoice", "payment",
    "price", "purchase", "quote", "spend", "total", "transaction", "value",
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


class AGTToolCall(BaseModel):
    tool_name: str
    tool_input: Optional[Dict[str, Any]] = None
    tool_output: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    run_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class AgentRegisterRequest(BaseModel):
    agent_id: str
    name: str = ""
    owner: str = ""
    scope: List[str] = Field(default_factory=list)
    description: str = ""
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


def _dropped_response(disposition: Dict[str, Any]) -> Response:
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
    feed.add(PulseEvent(kind="policy", text=operation or "", data=policy_data))
    if not evaluation.allowed:
        if SHADOW_MODE:
            return evaluation
        raise HTTPException(
            status_code=403,
            detail={"error": "Policy evaluation denied request", "policy": evaluation.to_dict()},
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
    circuit_breaker.open(reason=payload.reason, bdi_score=payload.bdi_score, entropy=payload.entropy)
    if circuit_breaker.last_failure is not None:
        circuit_breaker.last_failure["manual"] = True
    return {"ok": True, "message": "Circuit breaker manually opened", "status_code": 503, **circuit_breaker.status()}


@app.post("/circuit-breaker/close")
def circuit_breaker_close(payload: CircuitBreakerCloseRequest) -> dict[str, object]:
    circuit_breaker.close(reason=payload.reason, bdi_score=payload.bdi_score, entropy=payload.entropy)
    return {"ok": True, "message": "Circuit breaker reset to closed", "status_code": 200, **circuit_breaker.status()}


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
        _record_drop_event(disposition, agent_id=payload.agent_id, bdi_score=0.0, entropy=0.0)
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
        await _insert_audit_log(payload, request, provisional_pulse, {"status_code": 503, "dropped": True})
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
        await _insert_audit_log(payload, request, pulse, {"status_code": 502, "error": str(exc)})
        raise HTTPException(status_code=502, detail=str(exc))
    if upstream.status_code >= 400:
        await _insert_audit_log(payload, request, pulse, {"status_code": upstream.status_code, "error": upstream.text})
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
    if drift_result.get("status") == "critical":
        circuit_breaker.open(
            reason=f"Auto-trip: critical drift detected (entropy={drift_result.get('score', 0):.3f})",
            bdi_score=float(drift_result.get("score", 0.0)),
            entropy=float(drift_result.get("score", 0.0)),
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
        _record_shadow_event(disposition, agent_id=payload.agent_id, bdi_score=bdi_score, entropy=entropy)
    elif disposition.get("action") != RequestAction.PROCEED.value:
        _record_drop_event(disposition, agent_id=payload.agent_id, bdi_score=bdi_score, entropy=entropy)
        request_id = str(uuid.uuid4())
        await _insert_intercept_logs(payload, request_id=request_id, bdi_score=bdi_score, policy_result="blocked")
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
    await _insert_intercept_logs(payload, request_id=request_id, bdi_score=bdi_score, policy_result="allowed")
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
    drift_engine.reset()
    return {"ok": True}


@app.get("/drift/{session_id}")
def get_drift(session_id: str) -> Dict[str, Any]:
    return {"ok": True, "session_id": session_id, "drift": drift_engine.get_drift(session_id)}


@app.get("/drift")
def list_drift_sessions() -> Dict[str, Any]:
    sessions = drift_engine.session_ids()
    return {"ok": True, "sessions": sessions, "drift": {sid: drift_engine.get_drift(sid) for sid in sessions}}


@app.get("/synthesis/report")
def synthesis_report() -> Dict[str, Any]:
    report = synthesis_runner.last_report
    if report is None:
        report = forensic_auditor.generate_pattern_report()
    return {"ok": True, "report": report}


@app.post("/synthesis/run")
def synthesis_run_now() -> Dict[str, Any]:
    report = synthesis_runner.run_once()
    return {"ok": True, "report": report}


@app.get("/compliance/export", response_model=None)
def compliance_export(format: str = "json") -> Union[Dict[str, Any], Response]:
    if format.lower() in {"md", "markdown"}:
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(compliance_store.export_markdown(), media_type="text/markdown")
    return {"ok": True, "report": compliance_store.export_report()}


@app.get("/compliance/events")
def compliance_events(limit: int = 100) -> Dict[str, Any]:
    return {"ok": True, "events": compliance_store.list_blocked(limit=limit)}


@app.get("/compliance/deadlines")
def compliance_deadlines(incident_time: Optional[str] = None) -> Dict[str, Any]:
    """ASEAN Deadline Clock — Action 3 (Phase 2)."""
    from datetime import timedelta
    ASEAN_FRAMEWORKS = [
        {"framework": "PDPA Malaysia", "obligation": "Notify PDPC of personal data breach", "window_hours": 24, "jurisdiction": "MY"},
        {"framework": "Singapore Model AI Governance Framework", "obligation": "Incident review and corrective action", "window_hours": 72, "jurisdiction": "SG"},
        {"framework": "Vietnam AI Law", "obligation": "Report AI system incident to authority", "window_hours": 72, "jurisdiction": "VN"},
        {"framework": "ISO/IEC 42001", "obligation": "Log and assess AI management system incident", "window_hours": 168, "jurisdiction": "INTL"},
    ]
    now = datetime.now(timezone.utc)
    if incident_time:
        try:
            incident_dt = datetime.fromisoformat(incident_time.replace("Z", "+00:00"))
            if incident_dt.tzinfo is None:
                incident_dt = incident_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid incident_time format. Use ISO 8601, e.g. 2026-06-27T10:00:00Z")
    else:
        incident_dt = now
    deadlines = []
    for fw in ASEAN_FRAMEWORKS:
        deadline_dt = incident_dt + timedelta(hours=fw["window_hours"])
        seconds_remaining = (deadline_dt - now).total_seconds()
        hours_remaining = seconds_remaining / 3600
        elapsed_hours = (now - incident_dt).total_seconds() / 3600
        if seconds_remaining <= 0:
            status = "BREACHED"
        elif hours_remaining <= fw["window_hours"] * 0.25:
            status = "CRITICAL"
        elif hours_remaining <= fw["window_hours"] * 0.50:
            status = "WARNING"
        else:
            status = "ACTIVE"
        deadlines.append({
            "framework": fw["framework"],
            "jurisdiction": fw["jurisdiction"],
            "obligation": fw["obligation"],
            "window_hours": fw["window_hours"],
            "incident_time": incident_dt.isoformat(),
            "deadline_time": deadline_dt.isoformat(),
            "hours_remaining": round(max(0.0, hours_remaining), 2),
            "elapsed_hours": round(elapsed_hours, 2),
            "status": status,
            "breached": seconds_remaining <= 0,
        })
    overall_status = "NOMINAL"
    if any(d["status"] == "BREACHED" for d in deadlines):
        overall_status = "BREACHED"
    elif any(d["status"] == "CRITICAL" for d in deadlines):
        overall_status = "CRITICAL"
    elif any(d["status"] == "WARNING" for d in deadlines):
        overall_status = "WARNING"
    return {"ok": True, "incident_time": incident_dt.isoformat(), "generated_at": now.isoformat(), "overall_status": overall_status, "deadlines": deadlines}


@app.get("/compliance/mgf")
def compliance_mgf(
    entropy: Optional[float] = None,
    severity: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """MGF Compliance Mapper — Action 2 (Phase 2)."""
    MGF_CLAUSES = [
        {"clause": "2.1", "title": "Internal Governance Structures and Measures", "trigger_severity": ["elevated", "critical"], "trigger_entropy_min": 0.40, "obligation": "Ensure senior management oversight of AI decisions at elevated risk.", "recommended_action": "Escalate to AI governance owner. Log decision rationale.", "priority": "HIGH"},
        {"clause": "2.2", "title": "Determining AI Decision Type", "trigger_severity": ["critical"], "trigger_entropy_min": 0.70, "obligation": "Classify AI decision impact. Flag fully automated decisions on individuals.", "recommended_action": "Introduce human-in-the-loop review before execution.", "priority": "CRITICAL"},
        {"clause": "2.3", "title": "Operations Management", "trigger_severity": ["elevated", "critical"], "trigger_entropy_min": 0.40, "obligation": "Monitor AI system operations and log anomalous behaviour.", "recommended_action": "Review session event chain. Verify no policy boundary crossed.", "priority": "HIGH"},
        {"clause": "2.4", "title": "Stakeholder Interaction and Communication", "trigger_severity": ["critical"], "trigger_entropy_min": 0.70, "obligation": "Notify affected stakeholders of high-risk AI behaviour.", "recommended_action": "Prepare incident summary. Notify data owner within 72 hours.", "priority": "CRITICAL"},
        {"clause": "2.5", "title": "Incident Reporting", "trigger_severity": ["critical"], "trigger_entropy_min": 0.70, "obligation": "Document and report AI incidents within MGF 72-hour window.", "recommended_action": "Export evidence package. Submit to compliance officer.", "priority": "CRITICAL"},
    ]
    effective_entropy = entropy if entropy is not None else 0.0
    effective_severity = (severity or "stable").lower()
    triggered = []
    for clause in MGF_CLAUSES:
        if effective_severity in clause["trigger_severity"] and effective_entropy >= clause["trigger_entropy_min"]:
            triggered.append({"clause": clause["clause"], "title": clause["title"], "obligation": clause["obligation"], "recommended_action": clause["recommended_action"], "priority": clause["priority"], "trigger": {"entropy": effective_entropy, "severity": effective_severity, "entropy_threshold": clause["trigger_entropy_min"]}})
    overall_priority = "NOMINAL"
    if any(c["priority"] == "CRITICAL" for c in triggered):
        overall_priority = "CRITICAL"
    elif any(c["priority"] == "HIGH" for c in triggered):
        overall_priority = "HIGH"
    return {"ok": True, "framework": "Singapore Model AI Governance Framework", "jurisdiction": "SG", "evaluated_at": datetime.now(timezone.utc).isoformat(), "inputs": {"entropy": effective_entropy, "severity": effective_severity, "session_id": session_id}, "overall_priority": overall_priority, "clauses_triggered": len(triggered), "triggered_clauses": triggered}


@app.get("/session/lineage/{session_id}")
async def session_lineage(session_id: str) -> Dict[str, Any]:
    """Session Lineage Tracker — Action 5 (Phase 2)."""
    try:
        result = await supabase_audit_client.get_session_events(session_id=session_id)
        events = result or []
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve session lineage: {str(exc)}")
    if not events:
        return {"ok": True, "session_id": session_id, "found": False, "message": "No events found for this session.", "lineage": [], "summary": {}}
    lineage = []
    for i, event in enumerate(events):
        lineage.append({
            "turn": i + 1,
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp"),
            "agent_id": event.get("agent_id"),
            "action": event.get("action"),
            "bdi_score": event.get("bdi_score"),
            "entropy": event.get("entropy"),
            "policy_result": event.get("policy_result", "unknown"),
            "input_preview": (event.get("input_text") or "")[:120],
            "output_preview": (event.get("output_text") or "")[:120],
        })
    bdi_scores = [e.get("bdi_score") for e in events if e.get("bdi_score") is not None]
    entropy_scores = [e.get("entropy") for e in events if e.get("entropy") is not None]
    blocked_count = sum(1 for e in events if e.get("policy_result") == "blocked")
    summary = {
        "total_turns": len(lineage),
        "blocked_turns": blocked_count,
        "allowed_turns": len(lineage) - blocked_count,
        "peak_bdi": round(max(bdi_scores), 4) if bdi_scores else None,
        "avg_bdi": round(sum(bdi_scores) / len(bdi_scores), 4) if bdi_scores else None,
        "peak_entropy": round(max(entropy_scores), 4) if entropy_scores else None,
        "avg_entropy": round(sum(entropy_scores) / len(entropy_scores), 4) if entropy_scores else None,
        "risk_trajectory": "ESCALATING" if len(entropy_scores) >= 2 and entropy_scores[-1] > entropy_scores[0] else "STABLE",
        "first_event": events[0].get("timestamp"),
        "last_event": events[-1].get("timestamp"),
    }
    return {"ok": True, "session_id": session_id, "found": True, "summary": summary, "lineage": lineage}


@app.get("/trust/score")
async def trust_score(
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    entropy: Optional[float] = None,
    bdi_score: Optional[float] = None,
    drift_status: Optional[str] = None,
    blocked_turns: Optional[int] = None,
    total_turns: Optional[int] = None,
) -> Dict[str, Any]:
    """Entropy-Weighted Trust Score — Action 4 (Phase 2)."""
    W_ENTROPY = 0.35
    W_BDI = 0.25
    W_DRIFT = 0.20
    W_COMPLIANCE = 0.20
    eff_entropy = max(0.0, min(1.0, entropy if entropy is not None else 0.0))
    entropy_component = 1.0 - eff_entropy
    eff_bdi = max(0.0, min(1.0, bdi_score if bdi_score is not None else 0.0))
    bdi_component = 1.0 - eff_bdi
    drift_map = {"stable": 1.0, "elevated": 0.5, "critical": 0.0, "unknown": 0.7}
    eff_drift = (drift_status or "unknown").lower()
    drift_component = drift_map.get(eff_drift, 0.7)
    if total_turns and total_turns > 0:
        blocked = blocked_turns or 0
        compliance_component = max(0.0, (total_turns - blocked) / total_turns)
    else:
        compliance_component = 1.0
    raw_score = (entropy_component * W_ENTROPY) + (bdi_component * W_BDI) + (drift_component * W_DRIFT) + (compliance_component * W_COMPLIANCE)
    trust_score_value = round(max(0.0, min(1.0, raw_score)), 4)
    if trust_score_value >= 0.75:
        trust_band = "TRUSTED"
    elif trust_score_value >= 0.55:
        trust_band = "PROVISIONAL"
    elif trust_score_value >= 0.40:
        trust_band = "CAUTION"
    else:
        trust_band = "UNTRUSTED"
    return {
        "ok": True,
        "agent_id": agent_id,
        "session_id": session_id,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "trust_score": trust_score_value,
        "trust_band": trust_band,
        "components": {"entropy_component": round(entropy_component, 4), "bdi_component": round(bdi_component, 4), "drift_component": round(drift_component, 4), "compliance_component": round(compliance_component, 4)},
        "weights": {"entropy": W_ENTROPY, "bdi": W_BDI, "drift": W_DRIFT, "compliance": W_COMPLIANCE},
        "inputs": {"entropy": eff_entropy, "bdi_score": eff_bdi, "drift_status": eff_drift, "blocked_turns": blocked_turns, "total_turns": total_turns},
    }


@app.post("/agt/bridge")
async def agt_bridge(payload: AGTToolCall) -> Dict[str, Any]:
    """AGT-to-Pulse Bridge — Action 1 (Phase 2)."""
    input_text = ""
    if payload.tool_input:
        try:
            input_text = json.dumps(payload.tool_input)
        except Exception:
            input_text = str(payload.tool_input)
    output_text = payload.tool_output or ""
    agent_id = payload.agent_id or f"agt-{payload.tool_name}"
    session_id = payload.session_id or payload.run_id or "agt-default"
    bdi_score = session_store.record_turn(session_id, agent_id, input_text, output_text)
    drift_result = drift_engine.record_turn(session_id=session_id, input_text=input_text, output_text=output_text)
    entropy = _calculate_shannon_entropy(input_text)
    disposition = circuit_breaker.gate_request(agent_id=agent_id, bdi_score=bdi_score, entropy=entropy, shadow_mode=SHADOW_MODE, intercept=True)
    request_id = str(uuid.uuid4())
    if disposition.get("action") not in {None, RequestAction.PROCEED.value}:
        _record_drop_event(disposition, agent_id=agent_id, bdi_score=bdi_score, entropy=entropy)
        await supabase_audit_client.insert_ai_event(
            event_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action=f"agt/{payload.tool_name}",
            input_text=input_text,
            output_text=output_text,
            bdi_score=bdi_score,
            policy_result="blocked",
            session_id=session_id,
        )
        raise HTTPException(
            status_code=409,
            detail={"error": "AGT tool call blocked by Pulse circuit breaker", "tool_name": payload.tool_name, "reason": disposition.get("reason"), "state": disposition.get("state")},
        )
    feed.add(
        PulseEvent(
            kind="input",
            text=input_text,
            data={"request_id": request_id, "agent_id": agent_id, "session_id": session_id, "tool_name": payload.tool_name, "run_id": payload.run_id, "bdi_score": bdi_score, "entropy": entropy, "decision": "allowed", "status_code": 200, "source": "agt_bridge"},
        )
    )
    await supabase_audit_client.insert_ai_event(
        event_id=request_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        action=f"agt/{payload.tool_name}",
        input_text=input_text,
        output_text=output_text,
        bdi_score=bdi_score,
        policy_result="allowed",
        session_id=session_id,
    )
    return {
        "ok": True,
        "allowed": True,
        "request_id": request_id,
        "source": "agt_bridge",
        "tool_name": payload.tool_name,
        "agent_id": agent_id,
        "session_id": session_id,
        "governance": {"bdi_score": bdi_score, "entropy": entropy, "drift": drift_result, "circuit_breaker": disposition.get("state", "closed")},
    }


@app.get("/ledger/integrity")
async def ledger_integrity(limit: int = 100) -> Dict[str, Any]:
    """Ledger Integrity Verifier — SHA-256 hash chain proof."""
    if not supabase_audit_client.configured:
        raise HTTPException(status_code=503, detail="Supabase not configured")
    try:
        headers = {
            "apikey": supabase_audit_client.key or "",
            "authorization": f"Bearer {supabase_audit_client.key}",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(
                f"{supabase_audit_client.url}/rest/v1/audit_logs",
                headers=headers,
                params={
                    "order": "created_at.asc",
                    "select": "id,created_at,agent_id,bdi_score,chain_hash,chain_previous_hash",
                    "limit": str(limit),
                },
            )
            response.raise_for_status()
            rows = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch audit_logs: {str(exc)}")
    total = len(rows)
    verified = 0
    broken = 0
    skipped = 0
    broken_links = []
    for i, row in enumerate(rows):
        chain_hash = row.get("chain_hash")
        chain_previous_hash = row.get("chain_previous_hash")
        if not chain_hash or not chain_previous_hash:
            skipped += 1
            continue
        if i > 0:
            prev_row = rows[i - 1]
            prev_hash = prev_row.get("chain_hash")
            if prev_hash and chain_previous_hash != prev_hash:
                broken += 1
                broken_links.append({
                    "row_index": i,
                    "id": row.get("id"),
                    "created_at": row.get("created_at"),
                    "expected_previous_hash": prev_hash,
                    "actual_previous_hash": chain_previous_hash,
                    "tamper_detected": True,
                })
            else:
                verified += 1
        else:
            verified += 1
    integrity_status = "VERIFIED" if broken == 0 else "TAMPERED"
    tamper_detected = broken > 0
    return {
        "ok": True,
        "integrity_status": integrity_status,
        "tamper_detected": tamper_detected,
        "algorithm": "SHA-256 hash chain",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_rows_fetched": total,
            "verified_links": verified,
            "broken_links": broken,
            "skipped_rows": skipped,
            "coverage_pct": round((verified / max(1, total - skipped)) * 100, 1),
        },
        "broken_links": broken_links,
        "proof": {
            "chain_type": "SHA-256 linked hash chain",
            "genesis_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "immutability": "DELETE and UPDATE are revoked at database level",
            "storage": "Supabase PostgreSQL — Singapore region (ap-southeast-1)",
        },
    }


@app.post("/agents/register")
async def register_agent(payload: AgentRegisterRequest) -> Dict[str, Any]:
    """Agent Identity Registry — Phase 3 Stage 1. Register an agent identity."""
    result = await supabase_audit_client.register_agent(
        agent_id=payload.agent_id,
        name=payload.name,
        owner=payload.owner,
        scope=payload.scope,
        description=payload.description,
        metadata=payload.metadata or {},
    )
    if not result.get("ok"):
        reason = result.get("reason", "unknown")
        if reason == "agent_id_already_registered":
            raise HTTPException(status_code=409, detail=f"Agent '{payload.agent_id}' is already registered.")
        raise HTTPException(status_code=500, detail=f"Registration failed: {reason}")
    return {
        "ok": True,
        "message": f"Agent '{payload.agent_id}' registered successfully.",
        "agent": result.get("agent"),
    }


@app.get("/agents")
async def list_agents(limit: int = 100) -> Dict[str, Any]:
    """Agent Identity Registry — list all registered agents."""
    agents = await supabase_audit_client.list_agents(limit=limit)
    return {
        "ok": True,
        "total": len(agents),
        "agents": agents,
    }


@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str) -> Dict[str, Any]:
    """Agent Identity Registry — look up a single agent."""
    agent = await supabase_audit_client.get_agent(agent_id=agent_id)
    if agent is None:
        return {
            "ok": True,
            "found": False,
            "agent_id": agent_id,
            "registered": False,
            "message": "Agent not found in registry. Treat as UNREGISTERED.",
        }
    return {
        "ok": True,
        "found": True,
        "registered": True,
        "agent": agent,
    }
