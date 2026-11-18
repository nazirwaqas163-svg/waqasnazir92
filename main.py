import os
import secrets
import hashlib
import json
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from dataclasses import asdict
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Union

import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from audit import GENESIS_HASH, supabase_audit_client, verify_ai_event_row
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
from swarm import swarm_detector
from shadow import compute_shadow, compute_trust_divergence
from topology import build_topology
from legal_hold import legal_hold_manager, evaluate_triggers
from passport import assemble_passport, render_pdf
from threat_classifier import threat_classifier
from org_policy_engine import evaluate_org_policies
from webhook_engine import fire_webhooks
from incident_report import assemble_evidence_package, render_incident_pdf
from trace_ingestion import normalize_span

APP_NAME = "pulse-proxy"
logger = logging.getLogger(__name__)
SYNTHESIS_ENABLED = os.getenv("PULSE_SYNTHESIS_ENABLED", "true").lower() in {"1", "true", "yes"}
SHADOW_MODE = os.getenv("PULSE_SHADOW_MODE", "false").lower() in {"1", "true", "yes"}
UPSTREAM_CHAT_URL = os.getenv("PULSE_UPSTREAM_CHAT_URL", "https://api.openai.com/v1/chat/completions")
UPSTREAM_API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("PULSE_UPSTREAM_API_KEY")
UPSTREAM_TIMEOUT = float(os.getenv("PULSE_UPSTREAM_TIMEOUT", "120"))
AGENT_COOLDOWN_SECONDS = float(os.getenv("PULSE_AGENT_COOLDOWN_SECONDS", "30"))
PULSE_ADMIN_API_KEY = os.getenv("PULSE_ADMIN_API_KEY", "")
PULSE_ADMIN_KEYS_JSON = os.getenv("PULSE_ADMIN_KEYS_JSON", "[]")
ALLOW_ANONYMOUS_DEMO = os.getenv("PULSE_ALLOW_ANONYMOUS_DEMO", "false").lower() in {"1", "true", "yes"}
BASELINE_MIN_TURNS = int(os.getenv("PULSE_BASELINE_MIN_TURNS", "5"))
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
# Phase 11 — Calibration Engine Constants
_REGULATORY_CLAIM_PATTERNS = [
    r'\bcomplies?\b', r'\bcompliant\b', r'\bpdpa\b', r'\bmgf\b',
    r'\bpersonal data protection\b', r'\bdata protection act\b',
    r'\biso.?42001\b', r'\bvietnam ai law\b', r'\bregulat\w+\b',
    r'\blegal\b', r'\blawful\b', r'\bpermitted\b', r'\brequired by law\b',
    r'\bmandatory\b', r'\bobligat\w+\b',
]
_TEMPORAL_CLAIM_PATTERNS = [
    r'\bcurrent\w*\b', r'\blatest\b', r'\bas of today\b', r'\bright now\b',
    r'\btoday\b', r'\bthis week\b', r'\bthis month\b', r'\bthis year\b',
    r'\brecent\w*\b', r'\bup.?to.?date\b', r'\blive\b', r'\breal.?time\b',
]
_CERTAINTY_WORDS = [
    r'\bis\b', r'\bwill\b', r'\bconfirmed?\b', r'\bguaranteed?\b',
    r'\bdefinitely\b', r'\bcertainly\b', r'\babsolutely\b', r'\bproven?\b',
    r'\bestablished\b', r'\bfact\b', r'\bfactually\b', r'\baccurate\b',
    r'\bexact\w*\b', r'\balways\b', r'\bnever\b', r'\bmust\b',
]
_HEDGE_WORDS = [
    r'\bapproximately\b', r'\blikely\b', r'\bmay\b', r'\bmight\b',
    r'\bcould\b', r'\bshould\b', r'\bprobably\b', r'\bpossibly\b',
    r'\bperhaps\b', r'\bseems?\b', r'\bappears?\b', r'\bsuggests?\b',
    r'\btypically\b', r'\bgenerally\b', r'\busually\b', r'\boften\b',
    r'\baround\b', r'\babout\b', r'\broughly\b', r'\bestimate\w*\b',
    r'\buncertain\b', r'\bunclear\b', r'\bcaveat\b', r'\bnote that\b',
]
_agent_calibration_history: Dict[str, List[float]] = {}
_agent_cache: Dict[str, Dict[str, Any]] = {}
AGENT_CACHE_TTL = 60.0

# ------------------------------------------------------------------
# Phase 9 — Multi-Tenancy: API key → org_id resolution
# ------------------------------------------------------------------
_org_cache: Dict[str, Dict[str, Any]] = {}
ORG_CACHE_TTL = 300.0  # 5-minute TTL

def _admin_principal(request: Request) -> Dict[str, str]:
    """Resolve a configured dashboard key to a named, role-scoped principal."""
    supplied = request.headers.get("x-admin-api-key", "")
    if not supplied:
        raise HTTPException(status_code=401, detail="Valid X-Admin-API-Key header required")
    try:
        configured = json.loads(PULSE_ADMIN_KEYS_JSON)
    except json.JSONDecodeError as exc:
        logger.error("PULSE_ADMIN_KEYS_JSON is invalid JSON")
        raise HTTPException(status_code=503, detail="Admin key configuration is invalid") from exc
    if not isinstance(configured, list):
        raise HTTPException(status_code=503, detail="Admin key configuration must be a JSON array")
    supplied_digest = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
    for entry in configured:
        if not isinstance(entry, dict) or not isinstance(entry.get("key"), str):
            continue
        configured_digest = hashlib.sha256(entry["key"].encode("utf-8")).hexdigest()
        if secrets.compare_digest(supplied_digest, configured_digest):
            role = str(entry.get("role", "viewer")).lower()
            if role not in {"viewer", "operator", "admin"}:
                continue
            return {"user_id": str(entry.get("user_id") or "dashboard-user"), "role": role}
    # Transition support: the single shared key remains an admin until rotated.
    if PULSE_ADMIN_API_KEY:
        legacy_digest = hashlib.sha256(PULSE_ADMIN_API_KEY.encode("utf-8")).hexdigest()
        if secrets.compare_digest(supplied_digest, legacy_digest):
            return {"user_id": "legacy-admin", "role": "admin"}
    raise HTTPException(status_code=401, detail="Valid X-Admin-API-Key header required")


def require_dashboard_access(request: Request) -> Dict[str, str]:
    """Require any named dashboard principal."""
    return _admin_principal(request)


def require_operator(request: Request) -> Dict[str, str]:
    """Require an operator or administrator for state-changing operations."""
    principal = _admin_principal(request)
    if principal["role"] not in {"operator", "admin"}:
        raise HTTPException(status_code=403, detail="Operator role required")
    return principal


def require_admin(request: Request) -> Dict[str, str]:
    """Require an administrator for tenant and access configuration."""
    principal = _admin_principal(request)
    if principal["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return principal

async def get_org_from_api_key(request: Request) -> Dict[str, Any]:
    """Resolve X-API-Key header to an org. Returns org dict or raises 401."""
    api_key = request.headers.get("x-api-key")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    key_digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    # Check cache
    cached = _org_cache.get(key_digest)
    if cached and time.monotonic() - cached["ts"] < ORG_CACHE_TTL:
        return cached["org"]
    if not supabase_audit_client.configured:
        raise HTTPException(status_code=503, detail="Organization key service is unavailable")
    # Look up in Supabase orgs table
    try:
        headers = {
            "apikey": supabase_audit_client.key or "",
            "authorization": f"Bearer {supabase_audit_client.key}",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{supabase_audit_client.url}/rest/v1/orgs",
                headers=headers,
                params={"api_key": f"eq.{key_digest}", "active": "eq.true", "limit": "1"},
            )
            response.raise_for_status()
            rows = response.json()
            # Continue accepting existing keys while customers rotate to hashed storage.
            if not rows:
                response = await client.get(
                    f"{supabase_audit_client.url}/rest/v1/orgs",
                    headers=headers,
                    params={"api_key": f"eq.{api_key}", "active": "eq.true", "limit": "1"},
                )
                response.raise_for_status()
                rows = response.json()
    except Exception as exc:
        logger.exception("Organization API key lookup failed")
        raise HTTPException(status_code=503, detail="Organization key service is unavailable") from exc
    if not rows:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    org = rows[0]
    _org_cache[key_digest] = {"org": org, "ts": time.monotonic()}
    return org


async def get_org_id_for_request(request: Request) -> str:
    """Resolve a verified organization, allowing anonymous demo traffic only by opt-in."""
    if request.headers.get("x-api-key"):
        org = await get_org_from_api_key(request)
        org_id = org.get("org_id")
        if not org_id:
            raise HTTPException(status_code=401, detail="API key has no organization")
        return str(org_id)
    if ALLOW_ANONYMOUS_DEMO:
        return "demo-org"
    raise HTTPException(status_code=401, detail="Valid X-API-Key header required")

def _cache_get(agent_id: str) -> Optional[Dict[str, Any]]:
    entry = _agent_cache.get(agent_id)
    if entry is None:
        return None
    if time.monotonic() - entry["ts"] > AGENT_CACHE_TTL:
        _agent_cache.pop(agent_id, None)
        return None
    return entry

def _cache_set(agent_id: str, found: bool) -> None:
    _agent_cache[agent_id] = {"found": found, "ts": time.monotonic()}

def _cache_invalidate(agent_id: str) -> None:
    _agent_cache.pop(agent_id, None)

async def _is_agent_registered(agent_id: str) -> bool:
    cached = _cache_get(agent_id)
    if cached is not None:
        return cached["found"]
    agent_info = await supabase_audit_client.get_agent(agent_id=agent_id)
    found = bool(agent_info and agent_info.get("found"))
    _cache_set(agent_id, found)
    return found

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

# Keep operational and customer data endpoints behind the dashboard admin key.
_ADMIN_PROTECTED_EXACT_PATHS = {
    "/admin/whoami",
    "/circuit-breaker/status", "/pulse", "/events", "/pulse/bdi", "/pulse/reset",
    "/drift", "/drift/recent", "/synthesis/report", "/synthesis/run",
    "/compliance/export", "/compliance/events", "/compliance/deadlines", "/compliance/mgf",
    "/trust/score", "/agt/bridge", "/ledger/integrity", "/ledger/integrity/ai_events",
    "/agents", "/agents/isolated", "/alerts", "/topology", "/swarm/detect", "/shadow/score",
    "/legal-hold", "/replay", "/orgs",
}


@app.middleware("http")
async def protect_sensitive_routes(request: Request, call_next):
    """Require the admin credential on sensitive dashboard and control-plane APIs."""
    # Let CORS handle browser preflight before checking headers that preflight omits.
    if request.method == "OPTIONS":
        return await call_next(request)
    path = request.url.path
    protected = path in _ADMIN_PROTECTED_EXACT_PATHS
    protected = protected or path.startswith(("/agents/", "/replay/"))
    protected = protected or (path.startswith("/legal-hold/") and not path.endswith("/view"))
    protected = protected or bool(re.fullmatch(r"/drift/[^/]+", path))
    protected = protected or bool(re.fullmatch(r"/session/(?:lineage|tree)/[^/]+", path))
    if protected:
        try:
            request.state.admin_principal = require_dashboard_access(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    response = await call_next(request)
    principal = getattr(request.state, "admin_principal", None)
    if principal and request.method not in {"GET", "HEAD", "OPTIONS"}:
        logger.info(
            "dashboard_action user_id=%s role=%s method=%s path=%s status=%s",
            principal["user_id"], principal["role"], request.method,
            request.url.path, response.status_code,
        )
    return response

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
    parent_session_id: Optional[str] = None
    input_text: str = ""
    output_text: str = ""
    metadata: Optional[Dict[str, Any]] = None
    bdi_score: Optional[float] = None
    entropy: Optional[float] = None
    self_reported_risk: Optional[float] = None

class AGTToolCall(BaseModel):
    tool_name: str
    tool_input: Optional[Dict[str, Any]] = None
    tool_output: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    parent_session_id: Optional[str] = None
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


class TraceBatchRequest(BaseModel):
    spans: List[Dict[str, Any]]

    class Config:
        extra = "forbid"

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
        # Phase FP-1: short messages (<15 chars) are not meaningful entropy signals
    # "hi", "ok", "yes" score artificially high due to low character diversity
    if len(text.strip()) < 15:
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
    prompt_text = _messages_text(payload.messages)
    amounts: List[Decimal] = []
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
    """Use the server's score only; never trust caller-supplied risk overrides."""
    try:
        score = float(pulse.get("bdi_score") or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return min(1.0, max(0.0, score)) if score == score else 0.0

def _effective_entropy(payload: ChatProxyRequest, prompt_text: str) -> float:
    """Calculate entropy from prompt text rather than accepting a client score."""
    score = float(_calculate_shannon_entropy(prompt_text))
    return min(1.0, max(0.0, score)) if score == score else 0.0

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

def _parent_session_id_from_payload(payload: ChatProxyRequest) -> Optional[str]:
    extra_fields = _extra_payload_fields(payload)
    value = extra_fields.get("parent_session_id")
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
    parent_session_id: Optional[str] = None,
    entropy: Optional[float] = None,
    org_id: Optional[str] = None,
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
        parent_session_id=parent_session_id,
        entropy=entropy,
        org_id=org_id,
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
        parent_session_id=_parent_session_id_from_payload(payload),
        entropy=pulse.get("entropy"),
    )

async def _insert_intercept_logs(
    payload: InterceptRequest,
    *,
    request_id: str,
    bdi_score: float,
    policy_result: str,
    entropy: Optional[float] = None,
    org_id: Optional[str] = None,
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
        parent_session_id=payload.parent_session_id,
        entropy=entropy,
        org_id=org_id,
    )

async def _maybe_open_legal_hold(
    *,
    org_id: Optional[str] = None,
    agent_id: Optional[str],
    session_id: Optional[str],
    event_id: Optional[str],
    drift_result: Optional[Dict[str, Any]] = None,
    shadow: Optional[Dict[str, Any]] = None,
    swarm: Optional[Dict[str, Any]] = None,
    deadlines: Optional[List[Dict[str, Any]]] = None,
    exfiltration: Optional[Dict[str, Any]] = None,
    policy_violations: Optional[List[Dict[str, Any]]] = None,
    calibration: Optional[Dict[str, Any]] = None,
    
) -> List[Dict[str, Any]]:
    # Phase 7 Stage 1 — Auto-Response Security Protocol:
    # exfiltration alerts, org policy violations, and live swarm suspicion
    # now auto-open legal holds with no manual dashboard action required.
    triggers = evaluate_triggers(
        drift_result=drift_result,
        shadow=shadow,
        swarm=swarm,
        deadlines=deadlines,
        exfiltration=exfiltration,
        policy_violations=policy_violations,
    )
    if not triggers:
        return []
    chain_hash = supabase_audit_client.get_chain_hash_local(event_id) if event_id else None
    opened: List[Dict[str, Any]] = []
    for t in triggers:
        hold = legal_hold_manager.create(
            trigger_type=t["trigger_type"],
            reason=t["reason"],
            severity=t.get("severity", "HIGH"),
            agent_id=agent_id,
            session_id=session_id,
            event_id=event_id,
            chain_hash=chain_hash,
            framework=t.get("framework"),
            jurisdiction=t.get("jurisdiction"),
            evidence={
                "drift": drift_result,
                "shadow": shadow,
                "exfiltration": exfiltration,
                "policy_violations": policy_violations,
                "swarm": swarm,
                "calibration": calibration,
            },
            dedupe_scope=t.get("dedupe_scope"),
        )
        if hold is None:
            continue
        feed.add(
            PulseEvent(
                kind="alert",
                text=t["reason"],
                data={
                    "decision": "alert",
                    "status_code": 200,
                    "severity": hold["severity"],
                    "trigger_type": hold["trigger_type"],
                    "legal_hold_id": hold["id"],
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "chain_hash": chain_hash,
                },
            )
        )
        await supabase_audit_client.insert_legal_hold(hold)
        # Phase 7 Stage 3 — auto-isolate the offending agent on swarm detection
        if hold["trigger_type"] == "swarm" and agent_id:
            session_store.isolate_agent(
                agent_id,
                reason=hold["reason"],
                hold_id=hold["id"],
                org_id=org_id or "global",
            )
            feed.add(
                PulseEvent(
                    kind="alert",
                    text=f"Agent {agent_id} isolated — swarm behaviour detected",
                    data={
                        "decision": "alert",
                        "status_code": 423,
                        "severity": "HIGH",
                        "trigger_type": "agent_isolated",
                        "agent_id": agent_id,
                        "reason": hold["reason"],
                        "hold_id": hold["id"],
                    },
                )
            )
            await _insert_ai_event_log(
                event_id=str(uuid.uuid4()),
                agent_id=agent_id,
                action="agent_isolated",
                input_text="",
                output_text=f"Agent isolated — swarm behaviour detected. Hold: {hold['id']}",
                bdi_score=None,
                policy_result="blocked",
                session_id=session_id,
                entropy=None,
            )
        # Phase 7 Stage 4 — auto-generate sealed incident report
        try:
            agent_events = await supabase_audit_client.get_recent_events(limit=500)
            agent_specific_events = [
                e for e in agent_events if e.get("agent_id") == agent_id
            ] if agent_id else []
            evidence_package = assemble_evidence_package(
                hold=hold,
                agent_events=agent_specific_events,
                exfiltration=exfiltration,
                policy_violations=policy_violations,
                swarm=swarm,
            )
            pdf_bytes = None
            try:
                pdf_bytes = render_incident_pdf(evidence_package)
            except RuntimeError:
                pass  # reportlab not installed — JSON-only mode
            await supabase_audit_client.insert_incident_report(
                hold_id=hold["id"],
                agent_id=agent_id,
                session_id=session_id,
                trigger_type=hold.get("trigger_type"),
                severity=hold.get("severity"),
                json_package=evidence_package,
                pdf_bytes=pdf_bytes,
            )
        except Exception:
            pass  # incident report failure must never block the governance engine
        # Phase 7 Stage 2 — fire signed webhook alerts for this hold
        org_id = hold.get("evidence", {}).get("org_id") or "demo-org"
        registrations = await supabase_audit_client.list_webhook_registrations(org_id=org_id)
        if registrations:
            await fire_webhooks(hold, registrations)
        opened.append(hold)
    return opened

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
def _count_cal_patterns(text: str, patterns: list) -> int:
    text_lower = text.lower()
    count = 0
    for p in patterns:
        count += len(re.findall(p, text_lower))
    return count


def compute_calibration(
    *,
    output_text: str,
    input_text: str,
    bdi_score: float,
    drift_score: float,
    entropy: float,
    baselined: bool,
    turns_analyzed: int,
    is_registered: bool,
    session_history_entropy: List[float],
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Phase 11 — Calibration scoring layer (7 signals)."""
    flags = []
    output = output_text or ""
    word_ct = max(1, len(output.split()))

    certainty_count = _count_cal_patterns(output, _CERTAINTY_WORDS)
    certainty_density = min(1.0, certainty_count / max(10, word_ct) * 10)
    evidence_quality = min(1.0, (
        (0.4 if baselined else 0.0) +
        (0.3 if is_registered else 0.0) +
        (0.3 * min(1.0, turns_analyzed / 10.0))
    ))
    confidence_evidence_gap = round(max(0.0, certainty_density - evidence_quality), 4)
    if confidence_evidence_gap > 0.5:
        flags.append("high_confidence_evidence_gap")

    assertion_density = round(min(1.0, certainty_count / max(5, word_ct) * 8), 4)
    if assertion_density > 0.7:
        flags.append("high_assertion_density")

    session_maturity = round(min(1.0, turns_analyzed / 10.0), 4)
    if session_maturity < 0.3 and assertion_density > 0.5:
        flags.append("low_session_maturity")

    length_certainty_risk = 0.0
    if word_ct < 20 and certainty_density > 0.4:
        length_certainty_risk = round(min(1.0, (0.4 / max(0.01, word_ct / 20)) * certainty_density), 4)
        flags.append("short_high_certainty_output")
    elif word_ct < 50 and certainty_density > 0.6:
        length_certainty_risk = round(min(1.0, certainty_density * 0.6), 4)

    compound_risk = round(min(1.0, bdi_score * 0.5 + drift_score * 0.5), 4)
    if bdi_score > 0.5 and assertion_density > 0.5:
        compound_risk = round(min(1.0, compound_risk + 0.2), 4)
        flags.append("bdi_calibration_compound")

    baseline_deviation = 0.0
    history = _agent_calibration_history.get(agent_id or "", [])
    if len(history) >= 3:
        hist_avg = sum(history[-10:]) / len(history[-10:])
        baseline_deviation = round(max(0.0, assertion_density - hist_avg), 4)
        if baseline_deviation > 0.25:
            flags.append("calibration_baseline_deviation")

    hedge_count = _count_cal_patterns(output, _HEDGE_WORDS)
    hedge_ratio = round(min(1.0, hedge_count / max(5, word_ct) * 8), 4)
    certainty_hedge_imbalance = round(max(0.0, certainty_density - hedge_ratio), 4)
    if certainty_hedge_imbalance > 0.6:
        flags.append("certainty_hedge_imbalance")

    reg_claim_count = _count_cal_patterns(output, _REGULATORY_CLAIM_PATTERNS)
    regulatory_claim_risk = 0.0
    regulatory_flags = []
    if reg_claim_count > 0 and hedge_ratio < 0.2 and certainty_density > 0.3:
        regulatory_claim_risk = round(min(1.0, reg_claim_count * 0.25), 4)
        flags.append("regulatory_claim_unverified")
        regulatory_flags.append({
            "type": "unverified_regulatory_claim",
            "count": reg_claim_count,
            "risk": regulatory_claim_risk,
            "asean_context": "Unverified definitive regulatory claims violate PDPA Malaysia §5 and Singapore MGF §2.2.",
        })

    temporal_count = _count_cal_patterns(output, _TEMPORAL_CLAIM_PATTERNS)
    temporal_risk = 0.0
    if temporal_count > 0 and certainty_density > 0.3:
        temporal_risk = round(min(1.0, temporal_count * 0.2 * certainty_density), 4)
        flags.append("temporal_claim_unverified")

    contradiction_risk = 0.0
    if len(session_history_entropy) >= 3:
        diffs = [abs(session_history_entropy[i] - session_history_entropy[i-1])
                 for i in range(1, len(session_history_entropy))]
        max_diff = max(diffs) if diffs else 0.0
        if max_diff > 0.3 and certainty_density > 0.4:
            contradiction_risk = round(min(1.0, max_diff * certainty_density), 4)
            flags.append("session_entropy_contradiction")

    calibration_score = round(min(1.0, max(0.0, (
        confidence_evidence_gap * 0.20 +
        assertion_density * 0.15 +
        (1.0 - session_maturity) * 0.10 +
        length_certainty_risk * 0.10 +
        compound_risk * 0.15 +
        baseline_deviation * 0.10 +
        certainty_hedge_imbalance * 0.10 +
        regulatory_claim_risk * 0.05 +
        temporal_risk * 0.03 +
        contradiction_risk * 0.02
    ))), 4)

    if agent_id:
        hist = _agent_calibration_history.setdefault(agent_id, [])
        hist.append(calibration_score)
        if len(hist) > 20:
            _agent_calibration_history[agent_id] = hist[-20:]

    if calibration_score >= 0.70:
        status = "SEVERELY_OVERCONFIDENT"
    elif calibration_score >= 0.50:
        status = "OVERCONFIDENT"
    elif calibration_score >= 0.30:
        status = "MILDLY_OVERCONFIDENT"
    else:
        status = "CALIBRATED"

    return {
        "score": calibration_score,
        "status": status,
        "flags": flags,
        "components": {
            "confidence_evidence_gap": confidence_evidence_gap,
            "assertion_density": assertion_density,
            "session_maturity": session_maturity,
            "length_certainty_risk": length_certainty_risk,
            "compound_risk": compound_risk,
            "baseline_deviation": baseline_deviation,
            "certainty_hedge_imbalance": certainty_hedge_imbalance,
            "regulatory_claim_risk": regulatory_claim_risk,
            "temporal_risk": temporal_risk,
            "contradiction_risk": contradiction_risk,
        },
        "vocabulary": {
            "certainty_count": certainty_count,
            "hedge_count": hedge_count,
            "regulatory_claim_count": reg_claim_count,
            "temporal_claim_count": temporal_count,
            "output_word_count": word_ct,
        },
        "regulatory_flags": regulatory_flags,
        "evidence_quality": evidence_quality,
        "asean_relevance": {
            "pdpa_malaysia": regulatory_claim_risk > 0.2 or temporal_risk > 0.3,
            "singapore_mgf": compound_risk > 0.5 or assertion_density > 0.6,
            "vietnam_ai_law": calibration_score > 0.5,
        },
    }
@app.get("/health")
def health() -> Dict[str, Any]:
    cb_snapshot = circuit_breaker.status()
    dependencies = {
        "supabase": supabase_audit_client.configured,
        "upstream_llm": bool(UPSTREAM_API_KEY),
    }
    degraded_reasons = []
    if not dependencies["supabase"]:
        degraded_reasons.append("organization storage and durable audit are unavailable")
    if not dependencies["upstream_llm"]:
        degraded_reasons.append("upstream LLM is not configured; baseline fallback is active")
    if SHADOW_MODE:
        degraded_reasons.append("shadow mode is enabled; policy decisions are not enforced")
    if not cb_snapshot["allows_requests"]:
        degraded_reasons.append("circuit breaker is open")
    return {
        "ok": True,
        "status": "degraded" if degraded_reasons else "healthy",
        "ready": not degraded_reasons,
        "degraded_reasons": degraded_reasons,
        "dependencies": dependencies,
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

@app.get("/admin/whoami")
def admin_whoami(principal: Dict[str, str] = Depends(require_dashboard_access)) -> Dict[str, str]:
    return principal


@app.get("/circuit-breaker/status")
def circuit_breaker_status() -> dict[str, object]:
    return circuit_breaker.status()

@app.post("/circuit-breaker/open")
def circuit_breaker_open(payload: CircuitBreakerOpenRequest, _admin: Dict[str, str] = Depends(require_operator)) -> dict[str, object]:
    circuit_breaker.open(reason=payload.reason, bdi_score=payload.bdi_score, entropy=payload.entropy)
    if circuit_breaker.last_failure is not None:
        circuit_breaker.last_failure["manual"] = True
    return {"ok": True, "message": "Circuit breaker manually opened", "status_code": 503, **circuit_breaker.status()}

@app.post("/circuit-breaker/close")
def circuit_breaker_close(payload: CircuitBreakerCloseRequest, _admin: Dict[str, str] = Depends(require_operator)) -> dict[str, object]:
    circuit_breaker.close(reason=payload.reason, bdi_score=payload.bdi_score, entropy=payload.entropy)
    return {"ok": True, "message": "Circuit breaker reset to closed", "status_code": 200, **circuit_breaker.status()}

@app.get("/pulse")
def pulse(limit: int = 50) -> Dict[str, Any]:
    return {"events": feed.list(limit=limit)}

@app.post("/pulse")
def pulse_tool_call(payload: PulseToolCallRequest, request: Request, _operator: Dict[str, str] = Depends(require_operator)):
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
    # The proxy uses a server-side upstream credential, so callers must belong to a known org.
    await get_org_from_api_key(request)
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
async def intercept(payload: InterceptRequest, request: Request) -> Dict[str, Any]:
    """SDK hook: record agent input/output and apply circuit-breaker governance.
    Phase 4 Stage 3: Threat Classification Layer (observation-only, no blocking).
    Phase 6 Stage 2: Org Policy Enforcement.
    Phase 7 Stage 1: Auto-Response — confirmed breaches auto-open legal holds.
    Phase 7 Stage 3: Agent Auto-Isolation — isolated agents receive 423 Locked.
    """
    org_id = await get_org_id_for_request(request)
    if not payload.session_id:
        payload.session_id = f"{payload.agent_id}:{uuid.uuid4()}"

    # Phase 7 Stage 3 — Agent Auto-Isolation: reject quarantined agents immediately
    if session_store.is_isolated(payload.agent_id, org_id=org_id):
        isolation = session_store.get_isolation(payload.agent_id, org_id=org_id)
        raise HTTPException(
            status_code=423,
            detail={
                "error": "Agent is isolated and cannot execute requests",
                "agent_id": payload.agent_id,
                "reason": isolation.reason if isolation else "quarantined",
                "isolated_at": isolation.isolated_at if isolation else None,
                "hold_id": isolation.hold_id if isolation else None,
                "release_endpoint": f"/agents/{payload.agent_id}/release?org_id={org_id}",
            },
        )

    bdi_score = session_store.record_turn(
        payload.session_id,
        payload.agent_id or "unknown",
        payload.input_text,
        payload.output_text,
    )
    drift_result = drift_engine.record_turn(
        session_id=payload.session_id,
        input_text=payload.input_text,
        output_text=payload.output_text,
    )
    if drift_result.get("status") == "critical":
        circuit_breaker.open(
            reason=f"Auto-trip: critical drift detected (entropy={drift_result.get('score', 0):.3f})",
            bdi_score=float(drift_result.get("score", 0.0)),
            entropy=float(drift_result.get("score", 0.0)),
        )

    drift_score = float(drift_result.get("score") or 0.0)
    baselined = (drift_result.get("turns_analyzed") or 0) >= BASELINE_MIN_TURNS
    components = drift_result.get("components") or {}
    token_collapse = float(components.get("token_collapse", 0.0))
    input_anomaly = float(components.get("input_anomaly", 0.0))
    exfiltration_risk_score = round((token_collapse * 0.25) + (input_anomaly * 0.75), 4)
    # Phase 7 Stage 1 fix: exfiltration alert (and therefore the auto legal
    # hold) only fires once the session is baselined (5+ analyzed turns),
    # matching the threat classifier's own suppression rule. Prevents a
    # CRITICAL hold from opening on turn 1 of every new session.
    exfiltration_alert = baselined and exfiltration_risk_score > 0.65
    if exfiltration_alert:
        feed.add(
            PulseEvent(
                kind="alert",
                text="Exfiltration risk detected",
                data={
                    "decision": "alert",
                    "status_code": 200,
                    "severity": "HIGH",
                    "trigger_type": "exfiltration",
                    "risk_score": exfiltration_risk_score,
                    "agent_id": payload.agent_id,
                    "session_id": payload.session_id,
                    "components": {
                        "token_collapse": token_collapse,
                        "input_anomaly": input_anomaly,
                    },
                },
            )
        )

    is_registered = await _is_agent_registered(payload.agent_id)
    unregistered = 0.0 if is_registered else 1.0
    has_parent = bool(payload.parent_session_id and payload.parent_session_id.strip())
    unauthorized_spawn = 0.0 if has_parent else 1.0

    shadow = compute_shadow(
        unregistered=unregistered,
        unauthorized_spawn=unauthorized_spawn,
        scope_violation=None,
        baselined=baselined,
        scope_measurable=False,
    )

    trust_divergence = compute_trust_divergence(
        payload.self_reported_risk, drift_score, baselined=baselined
    )

    active_sessions = session_store.active_sessions_for_agent(
        payload.agent_id, window_seconds=300
    )
    swarm_suspect = len(active_sessions) >= 3
    swarm_session_count = len(active_sessions)

    entropy = (
        float(payload.entropy)
        if payload.entropy is not None
        else _calculate_shannon_entropy(payload.input_text)
    )

    session_turns = await supabase_audit_client.get_session_turns(payload.session_id)
    policy_blocked_turns = sum(1 for e in session_turns if e.get("status") == "blocked")
    policy_total_turns = len(session_turns)

    threat_classification = threat_classifier.classify(
        exfiltration_risk=exfiltration_risk_score,
        unregistered=unregistered,
        unauthorized_spawn=unauthorized_spawn,
        scope_violation=None,
        swarm_suspect=swarm_suspect,
        swarm_session_count=swarm_session_count,
        drift_score=drift_score,
        entropy=entropy,
        policy_blocked_turns=policy_blocked_turns,
        policy_total_turns=policy_total_turns,
        baselined=baselined,
    )
    # ------------------------------------------------------------------
    # Phase 11 — Calibration Scoring Layer
    # ------------------------------------------------------------------
    session_entropy_history = [
        float(e.get("entropy") or 0.0)
        for e in session_turns
        if e.get("entropy") is not None
    ]
    calibration = compute_calibration(
        output_text=payload.output_text,
        input_text=payload.input_text,
        bdi_score=bdi_score,
        drift_score=drift_score,
        entropy=entropy,
        baselined=baselined,
        turns_analyzed=drift_result.get("turns_analyzed") or 0,
        is_registered=is_registered,
        session_history_entropy=session_entropy_history,
        agent_id=payload.agent_id,
    )
    if calibration["status"] in ("SEVERELY_OVERCONFIDENT", "OVERCONFIDENT"):
        feed.add(
            PulseEvent(
                kind="alert",
                text=f"Calibration failure: {calibration['status']} (score={calibration['score']})",
                data={
                    "decision": "alert",
                    "status_code": 200,
                    "severity": "HIGH" if calibration["status"] == "SEVERELY_OVERCONFIDENT" else "MEDIUM",
                    "trigger_type": "calibration_failure",
                    "calibration_score": calibration["score"],
                    "flags": calibration["flags"],
                    "agent_id": payload.agent_id,
                    "session_id": payload.session_id,
                },
            )
        )
    # ------------------------------------------------------------------
    # Phase 6 Stage 2 — Org Policy Enforcement
    # Load org policies and check input text against them.
    # Organization scope comes from a verified key, unless anonymous demo is explicitly enabled.
    # ------------------------------------------------------------------
    policy_violations = await evaluate_org_policies(
        input_text=payload.input_text,
        output_text=payload.output_text,
        org_id=org_id,
        supabase_client=supabase_audit_client,
    )
    if policy_violations:
        feed.add(
            PulseEvent(
                kind="alert",
                text=f"Org policy violation: {len(policy_violations)} rule(s) fired",
                data={
                    "decision": "alert",
                    "status_code": 200,
                    "severity": "HIGH",
                    "trigger_type": "policy_violation",
                    "violations": policy_violations,
                    "agent_id": payload.agent_id,
                    "session_id": payload.session_id,
                    "org_id": org_id,
                },
            )
        )

    disposition = circuit_breaker.gate_request(
        agent_id=payload.agent_id,
        bdi_score=bdi_score,
        entropy=entropy,
        shadow_mode=SHADOW_MODE,
        intercept=True,
        baselined=baselined,
        session_id=payload.session_id,
    )
    if disposition.get("shadow_mode") and disposition.get("would_have_action"):
        _record_shadow_event(disposition, agent_id=payload.agent_id, bdi_score=bdi_score, entropy=entropy)
    elif disposition.get("action") != RequestAction.PROCEED.value:
        _record_drop_event(disposition, agent_id=payload.agent_id, bdi_score=bdi_score, entropy=entropy)
        request_id = str(uuid.uuid4())
        await _insert_intercept_logs(payload, request_id=request_id, bdi_score=bdi_score, policy_result="blocked", entropy=entropy, org_id=org_id)
        holds = await _maybe_open_legal_hold(
            org_id=org_id,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
            event_id=request_id,
            drift_result=drift_result,
            shadow=shadow,
            swarm={
                "swarm_suspect": swarm_suspect,
                "active_sessions": swarm_session_count,
                "window_seconds": 300,
                "threshold": 3,
                "agent_id": payload.agent_id,
            },
            exfiltration={
                "alert": exfiltration_alert,
                "risk_score": exfiltration_risk_score,
                "components": {
                    "token_collapse": token_collapse,
                    "input_anomaly": input_anomaly,
                },
            },
            policy_violations=policy_violations,
            calibration=calibration,
        )
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Circuit breaker tripped",
                "reason": disposition.get("reason"),
                "state": disposition.get("state"),
                "action": disposition.get("action"),
                "shadow": shadow,
                "trust_divergence": trust_divergence,
                "threat_classification": threat_classification,
                "policy_violations": policy_violations,
                "calibration": calibration,
                "legal_holds": [h["id"] for h in holds],
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
                "parent_session_id": payload.parent_session_id,
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
    await _insert_intercept_logs(payload, request_id=request_id, bdi_score=bdi_score, policy_result="allowed", entropy=entropy, org_id=org_id)
    holds = await _maybe_open_legal_hold(
        org_id=org_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        event_id=request_id,
        drift_result=drift_result,
        shadow=shadow,
        swarm={
            "swarm_suspect": swarm_suspect,
            "active_sessions": swarm_session_count,
            "window_seconds": 300,
            "threshold": 3,
            "agent_id": payload.agent_id,
        },
        exfiltration={
            "alert": exfiltration_alert,
            "risk_score": exfiltration_risk_score,
            "components": {
                "token_collapse": token_collapse,
                "input_anomaly": input_anomaly,
            },
        },
        policy_violations=policy_violations,
        calibration=calibration,
    )
    return {
        "ok": True,
        "allowed": True,
        "output_text": payload.output_text,
        "request_id": request_id,
        "drift": drift_result,
        "shadow": shadow,
        "trust_divergence": trust_divergence,
        "swarm_check": {
            "swarm_suspect": swarm_suspect,
            "active_sessions": swarm_session_count,
            "window_seconds": 300,
            "threshold": 3,
        },
        "threat_classification": threat_classification,
        "policy_violations": policy_violations,
        "calibration": calibration,
        "legal_holds": [h["id"] for h in holds],
        "exfiltration": {
            "risk_score": exfiltration_risk_score,
            "alert": exfiltration_alert,
            "components": {
                "token_collapse": token_collapse,
                "input_anomaly": input_anomaly,
            },
        },
    }

@app.post("/pulse/reset")
def reset(_admin: Dict[str, str] = Depends(require_operator)) -> Dict[str, Any]:
    feed.clear()
    bdi_state.reset()
    session_store.reset()
    circuit_breaker.close(reason="manual reset", bdi_score=0.0, entropy=0.0)
    drift_engine.reset()
    legal_hold_manager.reset()
    _agent_cache.clear()
    return {"ok": True}

@app.get("/drift/recent")
async def get_recent_drift_scores(limit: int = 50) -> Dict[str, Any]:
    try:
        events = await supabase_audit_client.get_recent_events(limit=limit)
        result = []
        seen_sessions: set = set()
        for e in events:
            session_id = e.get("session_id")
            if not session_id or session_id in seen_sessions:
                continue
            seen_sessions.add(session_id)
            drift = drift_engine.get_drift(session_id)
            result.append({
                "session_id": session_id,
                "agent_id": e.get("agent_id"),
                "drift_score": float(drift.get("score", 0.0)),
                "drift_status": drift.get("status", "unknown"),
                "turns_analyzed": drift.get("turns_analyzed", 0),
                "turn_number": e.get("turn_number", 0),
                "timestamp": e.get("created_at"),
            })
        return {"ok": True, "total": len(result), "sessions": result}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

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
def synthesis_run_now(_operator: Dict[str, str] = Depends(require_operator)) -> Dict[str, Any]:
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
async def compliance_deadlines(incident_time: Optional[str] = None, auto_hold: bool = True) -> Dict[str, Any]:
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
        from datetime import timedelta
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
    if auto_hold:
        for d in deadlines:
            if not d.get("breached"):
                continue
            hold = legal_hold_manager.create(
                trigger_type="compliance_breach",
                reason=f"{d['framework']} reporting deadline breached",
                severity="CRITICAL",
                framework=d["framework"],
                jurisdiction=d["jurisdiction"],
                evidence={"incident_time": incident_dt.isoformat(), "window_hours": d["window_hours"]},
                dedupe_scope=d["framework"],
            )
            if hold is not None:
                feed.add(PulseEvent(kind="alert", text=hold["reason"], data={
                    "decision": "alert", "status_code": 200, "severity": "CRITICAL",
                    "trigger_type": "compliance_breach", "legal_hold_id": hold["id"],
                    "framework": d["framework"],
                }))
                await supabase_audit_client.insert_legal_hold(hold)
    return {"ok": True, "incident_time": incident_dt.isoformat(), "generated_at": now.isoformat(), "overall_status": overall_status, "deadlines": deadlines}

@app.get("/compliance/mgf")
def compliance_mgf(
    entropy: Optional[float] = None,
    severity: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
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
            parent_session_id=payload.parent_session_id,
            entropy=entropy,
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
        parent_session_id=payload.parent_session_id,
        entropy=entropy,
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
async def register_agent(payload: AgentRegisterRequest, _admin: None = Depends(require_admin)) -> Dict[str, Any]:
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
    _cache_invalidate(payload.agent_id)
    return {
        "ok": True,
        "message": f"Agent '{payload.agent_id}' registered successfully.",
        "agent": result.get("agent"),
    }

@app.get("/agents")
async def list_agents(limit: int = 100) -> Dict[str, Any]:
    agents = await supabase_audit_client.list_agents(limit=limit)
    return {
        "ok": True,
        "total": len(agents),
        "agents": agents,
    }

@app.get("/agents/isolated")
def list_isolated_agents(active_only: bool = True, org_id: Optional[str] = None) -> Dict[str, Any]:
    """List all currently isolated agents."""
    records = session_store.list_isolated(active_only=active_only, org_id=org_id)
    return {"ok": True, "total": len(records), "isolated_agents": records}
    
@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str) -> Dict[str, Any]:
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

class LegalHoldCreateRequest(BaseModel):
    trigger_type: str = "manual"
    reason: str
    severity: str = "HIGH"
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    event_id: Optional[str] = None
    framework: Optional[str] = None
    jurisdiction: Optional[str] = None

class LegalHoldReleaseRequest(BaseModel):
    released_by: str = "dashboard"
class OrgRegistrationRequest(BaseModel):
    org_name: str
    email: str

class OrgRegistrationResponse(BaseModel):
    org_id: str
    api_key: str
    dashboard_url: str
    message: str
class OrgPolicyRequest(BaseModel):
    org_id: str
    policy_id: str
    name: str
    rules: Dict[str, Any]
def generate_org_id(org_name: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '_', org_name.lower()).strip('_')[:20]
    suffix = secrets.token_hex(3)
    return f"{slug}_{suffix}"


def generate_api_key() -> str:
    return f"pulse_{secrets.token_hex(32)}"


def hash_api_key(api_key: str) -> str:
    """Return a one-way digest suitable for storage; issued keys have high entropy."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def send_welcome_email(to_email: str, org_name: str, api_key: str, org_id: str) -> bool:
    smtp_host = os.getenv("PULSE_SMTP_HOST")
    smtp_port = int(os.getenv("PULSE_SMTP_PORT", "587"))
    smtp_user = os.getenv("PULSE_SMTP_USER")
    smtp_pass = os.getenv("PULSE_SMTP_PASS")
    smtp_from = os.getenv("PULSE_SMTP_FROM", smtp_user)
    if not all([smtp_host, smtp_user, smtp_pass]):
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Welcome to Pulse — Your API Key & Dashboard Access"
        msg["From"] = smtp_from
        msg["To"] = to_email
        body = f"Welcome to Pulse, {org_name}!\n\nOrg ID: {org_id}\nAPI Key: {api_key}\n\nDashboard: https://pulse-dashboard-cx7x.onrender.com"
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [to_email], msg.as_string())
        return True
    except Exception:
        return False
@app.post("/org/policies")
async def create_org_policy(payload: OrgPolicyRequest, _admin: None = Depends(require_admin)) -> Dict[str, Any]:
    """Create or update org policy. Stored durably in Supabase."""
    try:
        result = await supabase_audit_client.insert_org_policy(
            org_id=payload.org_id,
            policy_id=payload.policy_id,
            name=payload.name,
            rules=payload.rules,
        )
        return {
            "ok": True,
            "created": True,
            "policy": result,
            "message": f"Policy '{payload.policy_id}' created for org '{payload.org_id}'",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/org/policies")
async def list_org_policies(org_id: str, _admin: None = Depends(require_admin)) -> Dict[str, Any]:
    """List all active policies for an org."""
    try:
        policies = await supabase_audit_client.list_org_policies(org_id=org_id)
        return {
            "ok": True,
            "org_id": org_id,
            "total": len(policies),
            "policies": policies,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.delete("/org/policies/{policy_id}")
async def delete_org_policy(policy_id: str, org_id: str, _admin: None = Depends(require_admin)) -> Dict[str, Any]:
    """Deactivate a policy (soft delete)."""
    try:
        result = await supabase_audit_client.deactivate_org_policy(
            policy_id=policy_id,
            org_id=org_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found")
        return {
            "ok": True,
            "deactivated": True,
            "policy_id": policy_id,
            "message": f"Policy '{policy_id}' deactivated",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

# ------------------------------------------------------------------
# Phase 7 Stage 2 — Webhook Registration Endpoints
# ------------------------------------------------------------------

class WebhookRegistrationRequest(BaseModel):
    org_id: str
    name: str
    url: str
    secret: str
    events: Optional[List[str]] = None

@app.post("/webhooks")
async def register_webhook(payload: WebhookRegistrationRequest, _admin: None = Depends(require_admin)) -> Dict[str, Any]:
    """Register a webhook URL to receive signed breach alerts."""
    try:
        result = await supabase_audit_client.insert_webhook_registration(
            org_id=payload.org_id,
            name=payload.name,
            url=payload.url,
            secret=payload.secret,
            events=payload.events or ["legal_hold.opened"],
        )
        if isinstance(result, dict) and result.get("ok") is False:
            raise HTTPException(status_code=500, detail=result.get("reason"))
        return {"ok": True, "created": True, "webhook": result}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/webhooks")
async def list_webhooks(org_id: str, _admin: None = Depends(require_admin)) -> Dict[str, Any]:
    """List active webhook registrations for an org."""
    try:
        webhooks = await supabase_audit_client.list_webhook_registrations(org_id=org_id)
        return {"ok": True, "org_id": org_id, "total": len(webhooks), "webhooks": webhooks}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, org_id: str, _admin: None = Depends(require_admin)) -> Dict[str, Any]:
    """Deactivate a webhook registration."""
    try:
        result = await supabase_audit_client.deactivate_webhook_registration(
            webhook_id=webhook_id, org_id=org_id
        )
        if not result:
            raise HTTPException(status_code=404, detail=f"Webhook '{webhook_id}' not found")
        return {"ok": True, "deactivated": True, "webhook_id": webhook_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

# ------------------------------------------------------------------
# Phase 7 Stage 3 — Agent Isolation Endpoints
# ------------------------------------------------------------------

class AgentIsolateRequest(BaseModel):
    org_id: str
    reason: str = "Manual isolation from dashboard"
    hold_id: Optional[str] = None

class AgentReleaseRequest(BaseModel):
    org_id: str
    released_by: str = "dashboard"

@app.post("/agents/{agent_id}/isolate")
async def isolate_agent(agent_id: str, payload: AgentIsolateRequest, _operator: Dict[str, str] = Depends(require_operator)) -> Dict[str, Any]:
    """Quarantine an agent — all future /intercept calls return 423 Locked."""
    record = session_store.isolate_agent(
        agent_id, reason=payload.reason, hold_id=payload.hold_id, org_id=payload.org_id
    )
    feed.add(
        PulseEvent(
            kind="alert",
            text=f"Agent {agent_id} manually isolated",
            data={
                "decision": "alert",
                "status_code": 423,
                "severity": "HIGH",
                "trigger_type": "agent_isolated",
                "agent_id": agent_id,
                "reason": payload.reason,
                "hold_id": payload.hold_id,
            },
        )
    )
    await _insert_ai_event_log(
        event_id=str(uuid.uuid4()),
        agent_id=agent_id,
        action="agent_isolated",
        input_text="",
        output_text=f"Agent manually isolated. Reason: {payload.reason}",
        bdi_score=None,
        policy_result="blocked",
        session_id=None,
        entropy=None,
        org_id=payload.org_id,
    )
    return {"ok": True, "isolated": True, "isolation": record.to_dict()}

@app.post("/agents/{agent_id}/release")
async def release_agent(agent_id: str, payload: AgentReleaseRequest, _operator: Dict[str, str] = Depends(require_operator)) -> Dict[str, Any]:
    """Release an agent from isolation."""
    record = session_store.release_agent(agent_id, released_by=payload.released_by, org_id=payload.org_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' is not isolated")
    return {"ok": True, "released": True, "isolation": record.to_dict()}



# ------------------------------------------------------------------
# Phase 7 Stage 4 — Evidence Package Endpoints
# ------------------------------------------------------------------

@app.get("/legal-hold/{hold_id}/evidence-package")
async def get_evidence_package(hold_id: str, format: str = "json") -> Any:
    """
    Download the sealed incident evidence package for a legal hold.
    format=json (default) — returns the JSON evidence package
    format=pdf            — returns the downloadable signed PDF
    """
    report = await supabase_audit_client.get_incident_report(hold_id=hold_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"No evidence package found for hold '{hold_id}'. "
                   "It may still be generating or the hold may not exist.",
        )
    if format.lower() == "pdf":
        import base64
        from fastapi.responses import Response as FastAPIResponse
        pdf_b64 = report.get("pdf_bytes")
        if not pdf_b64:
            raise HTTPException(
                status_code=404,
                detail="PDF not available for this report (reportlab may not be installed).",
            )
        pdf_bytes = base64.b64decode(pdf_b64)
        filename = f"pulse-incident-{hold_id[:8]}.pdf"
        return FastAPIResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    return {
        "ok": True,
        "hold_id": hold_id,
        "report_id": report.get("id"),
        "generated_at": report.get("generated_at"),
        "sealed": report.get("sealed"),
        "evidence_package": report.get("json_package"),
    }

@app.post("/legal-hold/{hold_id}/evidence-package/send")
async def send_evidence_package(hold_id: str, dpo_email: str, _operator: Dict[str, str] = Depends(require_operator)) -> Dict[str, Any]:
    """
    Phase 7 Stage 4 — Send the sealed evidence package to a DPO email.
    Note: requires SMTP configuration via environment variables
    PULSE_SMTP_HOST, PULSE_SMTP_PORT, PULSE_SMTP_USER, PULSE_SMTP_PASS.
    """
    report = await supabase_audit_client.get_incident_report(hold_id=hold_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"No evidence package found for hold '{hold_id}'")

    smtp_host = os.getenv("PULSE_SMTP_HOST")
    if not smtp_host:
        return {
            "ok": False,
            "message": "SMTP not configured. Set PULSE_SMTP_HOST, PULSE_SMTP_PORT, PULSE_SMTP_USER, PULSE_SMTP_PASS environment variables to enable DPO email delivery.",
            "hold_id": hold_id,
            "dpo_email": dpo_email,
        }

    try:
        import smtplib
        import base64
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.application import MIMEApplication

        smtp_port = int(os.getenv("PULSE_SMTP_PORT", "587"))
        smtp_user = os.getenv("PULSE_SMTP_USER", "")
        smtp_pass = os.getenv("PULSE_SMTP_PASS", "")

        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = dpo_email
        msg["Subject"] = f"Pulse Incident Evidence Package — Hold {hold_id[:8]}"

      # PDPA-compliant DPO notification
        incident_time = report.get("generated_at", datetime.now(timezone.utc).isoformat())
        trigger_type_rep = report.get("trigger_type", "data_breach")
        severity_rep = report.get("severity", "HIGH")
        agent_id_rep = report.get("agent_id", "unknown")
        json_pkg = report.get("json_package") or {}
        seal_hash_rep = json_pkg.get("seal_hash", "—")
        chain_hash_rep = json_pkg.get("chain_hash", "—")
        tsa_status_rep = json_pkg.get("tsa_status", "INTERNAL_SEAL_ONLY")
        tsa_stamped_rep = json_pkg.get("tsa_stamped_at", "—")

        body = f"""PERSONAL DATA BREACH NOTIFICATION
Pursuant to Malaysia Personal Data Protection Act 2010 (Amended 2024)
Section 30 — Mandatory Breach Notification

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Dear Data Protection Officer,

This notice is issued by the Pulse AI Governance Engine to inform your office of a
detected AI agent security incident that may constitute a personal data breach under
PDPA Malaysia (Amended 2024).

INCIDENT REFERENCE
  Legal Hold ID  : {hold_id}
  Agent ID       : {agent_id_rep}
  Detected At    : {incident_time}
  Trigger Type   : {trigger_type_rep}
  Severity       : {severity_rep}

EVIDENCE INTEGRITY
  Seal Hash      : {seal_hash_rep}
  Chain Hash     : {chain_hash_rep}
  Timestamp Auth : {tsa_status_rep}
  TSA Stamped At : {tsa_stamped_rep}

The sealed evidence package is attached as a PDF. It contains:
  - Full incident timeline and agent session lineage
  - BDI behavioural divergence scores and entropy readings
  - Threat classification and exfiltration risk signals
  - SHA-256 tamper-evident seal (independently verifiable)
  - RFC 3161 trusted timestamp certificate (where available)
  - ASEAN regulatory mapping and notification deadlines

REGULATORY OBLIGATIONS
  Malaysia PDPA 2010 (s.30) : Notify PDPC within 72 hours (recommended 24hr)
  Singapore PDPC            : Notify within 3 calendar days if >500 individuals affected
  Vietnam AI Law Art. 9     : Report to competent authority within 72 hours
  ISO/IEC 42001             : Document and retain record for minimum 7 years

ACTION REQUIRED
  1. Review the attached sealed evidence package immediately
  2. Assess whether the incident meets the mandatory notification threshold
  3. If threshold met - notify PDPC Malaysia at pdpc.complaints@pdpc.gov.my
  4. Preserve this email and attachment as part of your breach response record
  5. Log your assessment decision with reference to Hold ID: {hold_id}

This notification was generated automatically by Pulse AI Governance Middleware.
Evidence has been cryptographically sealed and timestamped. Do not alter or delete.

Verification: openssl ts -verify -in token.tsr -digest <seal_hash> -CAfile tsa_ca.pem

Pulse AI Governance Middleware
pulse-proxy-8dqx.onrender.com
Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONFIDENTIAL - FOR DESIGNATED DATA PROTECTION OFFICER ONLY
"""
        msg.attach(MIMEText(body, "plain"))

        pdf_b64 = report.get("pdf_bytes")
        if pdf_b64:
            pdf_bytes = base64.b64decode(pdf_b64)
            attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
            attachment.add_header(
                "Content-Disposition", "attachment",
                filename=f"pulse-incident-{hold_id[:8]}.pdf",
            )
            msg.attach(attachment)

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, dpo_email, msg.as_string())

        return {
            "ok": True,
            "sent": True,
            "hold_id": hold_id,
            "dpo_email": dpo_email,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email delivery failed: {str(exc)}")

@app.get("/swarm/detect")
async def swarm_detect(
    window_minutes: int = 60,
    min_cluster_size: int = 3,
    min_distinct_sessions: int = 2,
    limit: int = 500,
) -> Dict[str, Any]:
    events = await supabase_audit_client.get_recent_events(limit=limit)
    return swarm_detector.detect(
        events,
        window_minutes=window_minutes,
        min_cluster_size=min_cluster_size,
        min_distinct_sessions=min_distinct_sessions,
    )

@app.get("/shadow/score")
async def shadow_score(
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    agent_self_report: Optional[float] = None,
) -> Dict[str, Any]:
    is_registered = False
    if agent_id:
        is_registered = await _is_agent_registered(agent_id)
    unregistered = 0.0 if is_registered else 1.0
    unauthorized_spawn = 1.0
    baselined = False
    if session_id:
        drift = drift_engine.get_drift(session_id)
        baselined = (drift.get("turns_analyzed") or 0) >= BASELINE_MIN_TURNS
        events = await supabase_audit_client.get_recent_events(limit=100)
        session_events = [e for e in events if e.get("session_id") == session_id]
        has_parent = any(e.get("parent_session_id") for e in session_events)
        unauthorized_spawn = 0.0 if has_parent else 1.0
    shadow = compute_shadow(
        unregistered=unregistered,
        unauthorized_spawn=unauthorized_spawn,
        scope_violation=None,
        baselined=baselined,
        scope_measurable=False,
    )
    trust_div = None
    if agent_self_report is not None and session_id:
        drift = drift_engine.get_drift(session_id)
        pulse_score = float(drift.get("score") or 0.0)
        trust_div = compute_trust_divergence(agent_self_report, pulse_score, baselined=baselined)
    return {
        "ok": True,
        "agent_id": agent_id,
        "session_id": session_id,
        "shadow_score_v2": shadow,
        "trust_divergence": trust_div,
    }

@app.get("/topology")
async def topology(limit: int = 500) -> Dict[str, Any]:
    events = await supabase_audit_client.get_recent_events(limit=limit)
    agents = await supabase_audit_client.list_agents(limit=500)
    graph = build_topology(events, agents=agents, drift_lookup=drift_engine.get_drift)
    return {"ok": True, **graph}

@app.get("/ai_events/recent")
async def ai_events_recent(request: Request, limit: int = 500) -> Dict[str, Any]:
    org_id = await get_org_id_for_request(request)
    events = await supabase_audit_client.get_recent_events(limit=limit, org_id=org_id)
    return {"ok": True, "total": len(events), "events": events}


@app.post("/v1/traces", status_code=202)
async def ingest_trace_spans(payload: TraceBatchRequest, request: Request) -> Dict[str, Any]:
    """Ingest up to 100 tenant-scoped OpenTelemetry-style spans idempotently."""
    org_id = await get_org_id_for_request(request)
    if not payload.spans or len(payload.spans) > 100:
        raise HTTPException(status_code=422, detail="spans must contain between 1 and 100 records")
    encoded_size = len(json.dumps(payload.spans, ensure_ascii=False).encode("utf-8"))
    if encoded_size > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="trace batch exceeds the 2 MB limit")
    try:
        rows = [normalize_span(span, org_id) for span in payload.spans]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    identities = [(row["trace_id"], row["span_id"]) for row in rows]
    if len(identities) != len(set(identities)):
        raise HTTPException(status_code=422, detail="A batch cannot contain duplicate trace_id/span_id pairs")
    try:
        inserted = await supabase_audit_client.insert_trace_spans(rows)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"ok": True, "org_id": org_id, "received": len(rows), "inserted": inserted}


@app.get("/v1/traces")
async def list_recent_traces(request: Request, limit: int = Query(50, ge=1, le=200)) -> Dict[str, Any]:
    org_id = await get_org_id_for_request(request)
    try:
        spans = await supabase_audit_client.get_trace_spans(org_id=org_id, limit=limit)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"ok": True, "org_id": org_id, "count": len(spans), "spans": spans}


@app.get("/v1/traces/{trace_id}")
async def get_trace(trace_id: str, request: Request) -> Dict[str, Any]:
    if not re.fullmatch(r"[0-9a-fA-F]{32}", trace_id) or trace_id == "0" * 32:
        raise HTTPException(status_code=422, detail="trace_id must be a non-zero 32-character hexadecimal ID")
    org_id = await get_org_id_for_request(request)
    try:
        spans = await supabase_audit_client.get_trace_spans(org_id=org_id, trace_id=trace_id.lower())
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")
    return {"ok": True, "org_id": org_id, "trace_id": trace_id.lower(), "span_count": len(spans), "spans": spans}

@app.get("/alerts")
def alerts(limit: int = 50) -> Dict[str, Any]:
    recent = feed.list(limit=500)
    alert_events = [e for e in recent if e.get("kind") in {"alert", "shadow", "governance"}][:limit]
    return {
        "ok": True,
        "active_holds": legal_hold_manager.list(status="ACTIVE"),
        "alerts": alert_events,
    }

@app.get("/legal-hold")
async def list_holds(status: Optional[str] = None, limit: int = 100, source: str = "memory") -> Dict[str, Any]:
    if source == "db":
        holds = await supabase_audit_client.list_legal_holds(status=status, limit=limit)
    else:
        holds = legal_hold_manager.list(status=status, limit=limit)
    return {"ok": True, "total": len(holds), "holds": holds}

@app.get("/legal-hold/{hold_id}")
def get_hold(hold_id: str) -> Dict[str, Any]:
    hold = legal_hold_manager.get(hold_id)
    if hold is None:
        raise HTTPException(status_code=404, detail=f"Legal hold '{hold_id}' not found")
    return {"ok": True, "hold": hold}

@app.post("/legal-hold")
async def create_hold(payload: LegalHoldCreateRequest, _operator: Dict[str, str] = Depends(require_operator)) -> Dict[str, Any]:
    chain_hash = (
        supabase_audit_client.get_chain_hash_local(payload.event_id) if payload.event_id else None
    )
    hold = legal_hold_manager.create(
        trigger_type=payload.trigger_type,
        reason=payload.reason,
        severity=payload.severity,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        event_id=payload.event_id,
        chain_hash=chain_hash,
        framework=payload.framework,
        jurisdiction=payload.jurisdiction,
    )
    if hold is None:
        return {"ok": True, "created": False, "message": "An identical ACTIVE hold already exists."}
    feed.add(PulseEvent(kind="alert", text=payload.reason, data={
        "decision": "alert", "status_code": 200, "severity": hold["severity"],
        "trigger_type": hold["trigger_type"], "legal_hold_id": hold["id"],
    }))
    await supabase_audit_client.insert_legal_hold(hold)
    return {"ok": True, "created": True, "hold": hold}

@app.post("/legal-hold/{hold_id}/release")
async def release_hold(hold_id: str, payload: LegalHoldReleaseRequest, _operator: Dict[str, str] = Depends(require_operator)) -> Dict[str, Any]:
    hold = legal_hold_manager.release(hold_id, released_by=payload.released_by)
    if hold is None:
        raise HTTPException(status_code=404, detail=f"Legal hold '{hold_id}' not found")
    await supabase_audit_client.release_legal_hold(hold_id, released_by=payload.released_by)
    return {"ok": True, "hold": hold}

@app.get("/session/tree/{session_id}")
async def session_tree(session_id: str, limit: int = 500) -> Dict[str, Any]:
    events = await supabase_audit_client.get_recent_events(limit=limit)
    by_session: Dict[str, Dict[str, Any]] = {}
    children: Dict[str, List[str]] = {}
    for e in events:
        sid = e.get("session_id")
        if not sid:
            continue
        node = by_session.setdefault(sid, {
            "session_id": sid, "agent_id": e.get("agent_id"),
            "parent_session_id": e.get("parent_session_id"), "turns": 0, "blocked": 0,
        })
        node["turns"] += 1
        if e.get("status") == "blocked":
            node["blocked"] += 1
        if e.get("parent_session_id") and not node.get("parent_session_id"):
            node["parent_session_id"] = e.get("parent_session_id")
    for sid, node in by_session.items():
        pid = node.get("parent_session_id")
        if pid:
            children.setdefault(pid, []).append(sid)
    ancestors: List[Dict[str, Any]] = []
    cur = by_session.get(session_id, {}).get("parent_session_id")
    seen: set = set()
    while cur and cur in by_session and cur not in seen:
        seen.add(cur)
        ancestors.append(by_session[cur])
        cur = by_session[cur].get("parent_session_id")
    descendants: List[Dict[str, Any]] = []
    queue = list(children.get(session_id, []))
    seen_d: set = set()
    while queue:
        sid = queue.pop(0)
        if sid in seen_d:
            continue
        seen_d.add(sid)
        if sid in by_session:
            descendants.append(by_session[sid])
        queue.extend(children.get(sid, []))
    return {
        "ok": True,
        "session_id": session_id,
        "found": session_id in by_session,
        "node": by_session.get(session_id),
        "ancestors": ancestors,
        "descendants": descendants,
    }

@app.get("/ledger/integrity/ai_events")
async def ledger_integrity_ai_events(limit: int = 100) -> Dict[str, Any]:
    if not supabase_audit_client.configured:
        raise HTTPException(status_code=503, detail="Supabase not configured")
    rows = await supabase_audit_client.get_ai_events_chain(limit=limit)
    total = len(rows)
    known_hashes = {row.get("row_hash") for row in rows if row.get("row_hash")}
    invalid_hashes = []
    unresolved_predecessors = []
    verified_links = 0
    for row in rows:
        if not verify_ai_event_row(row):
            invalid_hashes.append(row.get("event_id"))
            continue
        previous_hash = row.get("prev_hash")
        if previous_hash == GENESIS_HASH:
            verified_links += 1
        elif previous_hash in known_hashes:
            verified_links += 1
        else:
            unresolved_predecessors.append({
                "event_id": row.get("event_id"),
                "previous_hash": previous_hash,
            })
    integrity_status = "TAMPERED" if invalid_hashes else "PARTIAL"
    return {
        "ok": True,
        "table": "ai_events",
        "integrity_status": integrity_status,
        "tamper_detected": bool(invalid_hashes),
        "algorithm": "SHA-256 hash chain",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_rows_fetched": total,
            "valid_row_hashes": total - len(invalid_hashes),
            "invalid_row_hashes": len(invalid_hashes),
            "verified_links": verified_links,
            "unresolved_predecessors": len(unresolved_predecessors),
        },
        "invalid_event_ids": invalid_hashes,
        "unresolved_predecessor_rows": unresolved_predecessors,
        "external_anchor_verified": False,
        "note": (
            "Each fetched row hash is recomputed from its stored event fields. "
            "This endpoint does not verify a complete chain outside the fetched rows "
            "or an independently stored checkpoint, so it never reports the full ledger as VERIFIED."
        ),
    }

@app.get("/agents/{agent_id}/passport")
async def agent_passport(
    agent_id: str,
    format: str = "json",
    session_id: Optional[str] = None,
) -> Any:
    """
    Pulse Passport PP-1 — signed compliance identity document per agent.
    format=json  → returns full passport as JSON (default)
    format=pdf   → returns downloadable signed PDF
    """
    from datetime import timedelta

    agent = await supabase_audit_client.get_agent(agent_id=agent_id)
    events = await supabase_audit_client.get_recent_events(limit=500)
    agent_events = [e for e in events if e.get("agent_id") == agent_id]

    if session_id:
        drift = drift_engine.get_drift(session_id)
    else:
        session_counts: Dict[str, int] = {}
        for e in agent_events:
            sid = e.get("session_id")
            if sid:
                session_counts[sid] = session_counts.get(sid, 0) + 1
        best_session = max(session_counts, key=session_counts.get) if session_counts else None
        drift = drift_engine.get_drift(best_session) if best_session else {}

    is_registered = await _is_agent_registered(agent_id)
    unregistered = 0.0 if is_registered else 1.0
    has_parent = any(e.get("parent_session_id") for e in agent_events)
    unauthorized_spawn = 0.0 if has_parent else 1.0
    baselined = (drift.get("turns_analyzed") or 0) >= BASELINE_MIN_TURNS
    shadow = compute_shadow(
        unregistered=unregistered,
        unauthorized_spawn=unauthorized_spawn,
        scope_violation=None,
        baselined=baselined,
        scope_measurable=False,
    )

    now = datetime.now(timezone.utc)
    ASEAN_FRAMEWORKS = [
        {"framework": "PDPA Malaysia", "obligation": "Notify PDPC of personal data breach", "window_hours": 24, "jurisdiction": "MY"},
        {"framework": "Singapore Model AI Governance Framework", "obligation": "Incident review and corrective action", "window_hours": 72, "jurisdiction": "SG"},
        {"framework": "Vietnam AI Law", "obligation": "Report AI system incident to authority", "window_hours": 72, "jurisdiction": "VN"},
        {"framework": "ISO/IEC 42001", "obligation": "Log and assess AI management system incident", "window_hours": 168, "jurisdiction": "INTL"},
    ]
    deadlines = []
    for fw in ASEAN_FRAMEWORKS:
        deadlines.append({
            "framework": fw["framework"],
            "jurisdiction": fw["jurisdiction"],
            "obligation": fw["obligation"],
            "window_hours": fw["window_hours"],
            "hours_remaining": float(fw["window_hours"]),
            "status": "ACTIVE",
            "breached": False,
        })

    all_holds = legal_hold_manager.list(status="ACTIVE")
    agent_holds = [h for h in all_holds if h.get("agent_id") == agent_id]
    db_holds = await supabase_audit_client.list_legal_holds(status="ACTIVE", limit=100)
    db_agent_holds = [h for h in db_holds if h.get("agent_id") == agent_id]
    hold_map = {h["id"]: h for h in agent_holds}
    for h in db_agent_holds:
        hold_map.setdefault(h["id"], h)
    merged_holds = list(hold_map.values())

    passport = assemble_passport(
        agent_id=agent_id,
        agent=agent,
        events=agent_events,
        drift=drift,
        shadow=shadow,
        deadlines=deadlines,
        holds=merged_holds,
    )

    if format.lower() == "pdf":
        try:
            pdf_bytes = render_pdf(passport)
        except RuntimeError as exc:
            raise HTTPException(status_code=501, detail=str(exc))
        from fastapi.responses import Response as FastAPIResponse
        filename = f"pulse-passport-{agent_id}.pdf"
        return FastAPIResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return {"ok": True, "passport": passport}
# ------------------------------------------------------------------
# Read-Only Audit Viewer — shareable expiring link, no credentials needed
# ------------------------------------------------------------------

import hashlib as _hashlib
import hmac as _hmac

VIEWER_SECRET = os.getenv("PULSE_VIEWER_SECRET", "pulse-viewer-secret-change-in-prod")
VIEWER_TTL_SECONDS = int(os.getenv("PULSE_VIEWER_TTL", "86400"))  # 24 hours


def _generate_viewer_token(hold_id: str) -> str:
    expires = int(time.time()) + VIEWER_TTL_SECONDS
    payload = f"{hold_id}:{expires}"
    sig = _hmac.new(VIEWER_SECRET.encode(), payload.encode(), _hashlib.sha256).hexdigest()
    return f"{expires}:{sig}"


def _verify_viewer_token(hold_id: str, token: str) -> bool:
    try:
        expires_str, sig = token.split(":", 1)
        expires = int(expires_str)
        if time.time() > expires:
            return False
        payload = f"{hold_id}:{expires}"
        expected = _hmac.new(VIEWER_SECRET.encode(), payload.encode(), _hashlib.sha256).hexdigest()
        return _hmac.compare_digest(sig, expected)
    except Exception:
        return False


@app.get("/legal-hold/{hold_id}/view-link")
async def get_viewer_link(hold_id: str) -> Dict[str, Any]:
    """
    Generate a shareable read-only viewer link for an incident report.
    Expires after PULSE_VIEWER_TTL seconds (default 24 hours).
    Safe to share with auditors and regulators — no login required.
    """
    report = await supabase_audit_client.get_incident_report(hold_id=hold_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"No evidence package found for hold '{hold_id}'")
    token = _generate_viewer_token(hold_id)
    expires_ts = int(token.split(":")[0])
    expires_dt = datetime.fromtimestamp(expires_ts, tz=timezone.utc).isoformat()
    base_url = os.getenv("PULSE_PUBLIC_URL", "https://pulse-proxy-8dqx.onrender.com")
    viewer_url = f"{base_url}/legal-hold/{hold_id}/view?token={token}"
    return {
        "ok": True,
        "hold_id": hold_id,
        "viewer_url": viewer_url,
        "expires_at": expires_dt,
        "ttl_hours": VIEWER_TTL_SECONDS // 3600,
        "note": "Share with auditors or regulators. No login required. Link expires after TTL.",
    }


@app.get("/legal-hold/{hold_id}/view")
async def view_incident_report(hold_id: str, token: str) -> Any:
    """
    Read-only audit viewer — token-authenticated, expiring, no credentials.
    Returns a self-contained HTML page with the full incident report.
    """
    from fastapi.responses import HTMLResponse

    if not _verify_viewer_token(hold_id, token):
        return HTMLResponse(content="""<!DOCTYPE html>
<html><head><title>Link Expired</title>
<style>body{font-family:system-ui;background:#0f172a;color:#f8fafc;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0;}
.box{text-align:center;padding:40px;border:1px solid #334155;border-radius:12px;}</style>
</head><body><div class="box">
<h2>🔒 Link Expired or Invalid</h2>
<p style="color:#64748b;margin-top:12px">This audit viewer link has expired or is invalid.</p>
<p style="color:#64748b;margin-top:8px">Please request a new link from your Pulse administrator.</p>
</div></body></html>""", status_code=401)

    report = await supabase_audit_client.get_incident_report(hold_id=hold_id)
    if not report:
        return HTMLResponse(content="<h1>Report not found</h1>", status_code=404)

    pkg = report.get("json_package") or {}
    tsa_status = pkg.get("tsa_status", "INTERNAL_SEAL_ONLY")
    tsa_stamped = pkg.get("tsa_stamped_at", "—")
    tsa_badge = "✅ RFC 3161 TIMESTAMPED" if tsa_status == "RFC_3161_STAMPED" else "⚠️ INTERNAL SEAL ONLY"
    tsa_color = "#10b981" if tsa_status == "RFC_3161_STAMPED" else "#f59e0b"
    exfil = pkg.get("exfiltration") or {}
    pviol = pkg.get("policy_violations") or []
    swarm = pkg.get("swarm") or {}
    expires_ts = int(token.split(":")[0])
    expires_dt = datetime.fromtimestamp(expires_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pulse Incident Report — {hold_id[:12]}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#f8fafc;padding:24px}}
  .header{{border-bottom:1px solid #334155;padding-bottom:20px;margin-bottom:24px}}
  .logo{{font-size:24px;font-weight:800;color:#3b82f6;letter-spacing:2px}}
  .subtitle{{color:#64748b;font-size:13px;margin-top:4px}}
  .badges{{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}}
  .badge{{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600}}
  .badge-red{{background:#7f1d1d;color:#fca5a5}}
  .badge-blue{{background:#1e3a5f;color:#93c5fd}}
  .badge-tsa{{background:#1c1917;color:{tsa_color};border:1px solid {tsa_color}}}
  .section{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:16px}}
  .section-title{{font-size:12px;font-weight:700;color:#3b82f6;text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}}
  .kv{{display:grid;grid-template-columns:180px 1fr;gap:8px 16px}}
  .kv-label{{color:#64748b;font-size:12px}}
  .kv-value{{color:#f8fafc;font-size:12px;font-family:monospace;word-break:break-all}}
  .hash{{font-family:monospace;font-size:11px;color:#94a3b8;word-break:break-all;padding:10px;background:#0f172a;border-radius:6px;margin-top:8px}}
  .footer{{text-align:center;color:#475569;font-size:11px;margin-top:24px;padding-top:16px;border-top:1px solid #1e293b}}
  .warning{{background:#1c1003;border:1px solid #78350f;border-radius:8px;padding:12px 16px;color:#fbbf24;font-size:12px;margin-bottom:16px}}
  .reg-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
  .reg-card{{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px}}
  .reg-country{{font-weight:700;font-size:13px}}
  .reg-law{{font-size:11px;color:#64748b;margin:4px 0}}
  .reg-deadline{{font-size:12px;color:#ef4444;font-weight:600}}
</style>
</head>
<body>
<div class="header">
  <div class="logo">PULSE</div>
  <div class="subtitle">AI Agent Governance Middleware · Read-Only Incident Report</div>
  <div class="badges">
    <span class="badge badge-red">CONFIDENTIAL — REGULATORY EVIDENCE</span>
    <span class="badge badge-blue">{(pkg.get("severity") or "UNKNOWN").upper()}</span>
    <span class="badge badge-tsa">{tsa_badge}</span>
  </div>
</div>
<div class="warning">⏱ This link expires at <strong>{expires_dt}</strong> · Read-only · No login required</div>
<div class="section">
  <div class="section-title">§1 — Incident Summary</div>
  <div class="kv">
    <span class="kv-label">Hold ID</span><span class="kv-value">{pkg.get("hold_id", hold_id)}</span>
    <span class="kv-label">Agent ID</span><span class="kv-value">{pkg.get("agent_id", "—")}</span>
    <span class="kv-label">Session ID</span><span class="kv-value">{pkg.get("session_id", "—")}</span>
    <span class="kv-label">Trigger Type</span><span class="kv-value">{pkg.get("trigger_type", "—")}</span>
    <span class="kv-label">Severity</span><span class="kv-value">{pkg.get("severity", "—")}</span>
    <span class="kv-label">Status</span><span class="kv-value">{pkg.get("status", "—")}</span>
    <span class="kv-label">Detected At</span><span class="kv-value">{pkg.get("created_at", "—")}</span>
    <span class="kv-label">Framework</span><span class="kv-value">{pkg.get("framework", "—")}</span>
    <span class="kv-label">Jurisdiction</span><span class="kv-value">{pkg.get("jurisdiction", "—")}</span>
  </div>
</div>
<div class="section">
  <div class="section-title">§2 — Detection Signals</div>
  <div class="kv">
    <span class="kv-label">Exfiltration Risk</span><span class="kv-value">{exfil.get("risk_score", "—")}</span>
    <span class="kv-label">Exfiltration Alert</span><span class="kv-value">{exfil.get("alert", False)}</span>
    <span class="kv-label">Swarm Suspect</span><span class="kv-value">{swarm.get("swarm_suspect", False)}</span>
    <span class="kv-label">Policy Violations</span><span class="kv-value">{len(pviol)}</span>
    <span class="kv-label">Event Count</span><span class="kv-value">{pkg.get("event_count", "—")}</span>
  </div>
</div>
<div class="section">
  <div class="section-title">§3 — RFC 3161 Trusted Timestamp</div>
  <div class="kv">
    <span class="kv-label">TSA Status</span><span class="kv-value" style="color:{tsa_color}">{tsa_status}</span>
    <span class="kv-label">TSA Stamped At</span><span class="kv-value">{tsa_stamped}</span>
    <span class="kv-label">TSA Endpoint</span><span class="kv-value">{pkg.get("tsa_endpoint", "—")}</span>
  </div>
  <div class="hash">Seal Hash: {pkg.get("seal_hash", "—")}</div>
  <div class="hash" style="margin-top:6px">Chain Hash: {pkg.get("chain_hash", "—")}</div>
</div>
<div class="section">
  <div class="section-title">§4 — ASEAN Regulatory Obligations</div>
  <div class="reg-grid">
    <div class="reg-card"><div class="reg-country">🇲🇾 Malaysia</div><div class="reg-law">PDPA 2010 (Amended 2024)</div><div class="reg-deadline">Notify within 72hr (rec. 24hr)</div></div>
    <div class="reg-card"><div class="reg-country">🇸🇬 Singapore</div><div class="reg-law">PDPA + Model AI Governance</div><div class="reg-deadline">Notify within 72hr</div></div>
    <div class="reg-card"><div class="reg-country">🇻🇳 Vietnam</div><div class="reg-law">AI Law 2024 (Art. 9)</div><div class="reg-deadline">Report within 72hr</div></div>
    <div class="reg-card"><div class="reg-country">🌐 Regional</div><div class="reg-law">ISO/IEC 42001</div><div class="reg-deadline">Document within 168hr</div></div>
  </div>
</div>
<div class="section">
  <div class="section-title">§5 — Evidence Integrity</div>
  <div class="kv">
    <span class="kv-label">Package Fingerprint</span><span class="kv-value">{pkg.get("package_fingerprint", "—")}</span>
    <span class="kv-label">Package Version</span><span class="kv-value">{pkg.get("package_version", "—")}</span>
    <span class="kv-label">Storage Region</span><span class="kv-value">Supabase ap-southeast-1 (Singapore)</span>
  </div>
</div>
<div class="footer">
  Pulse AI Governance Middleware · ASEAN-native · Vendor-neutral · Intercepts before execution<br>
  Read-only view of a sealed forensic evidence package. Evidence cannot be altered via this interface.
</div>
</body></html>"""

    return HTMLResponse(content=html)
@app.post("/orgs/register", response_model=OrgRegistrationResponse)
async def register_org(request: OrgRegistrationRequest):
    org_name = request.org_name.strip()
    email = request.email.strip().lower()
    if not org_name:
        raise HTTPException(status_code=422, detail="org_name is required")
    if not email or "@" not in email:
        raise HTTPException(status_code=422, detail="Valid email is required")
    org_id = generate_org_id(org_name)
    api_key = generate_api_key()
    dashboard_url = "https://pulse-dashboard-cx7x.onrender.com"
    try:
        headers = {
            "apikey": supabase_audit_client.key or "",
            "authorization": f"Bearer {supabase_audit_client.key}",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{supabase_audit_client.url}/rest/v1/orgs",
                headers=headers,
                json={"org_id": org_id, "name": org_name, "api_key": hash_api_key(api_key), "email": email, "active": True},
            )
            resp.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to create organisation")
    email_sent = send_welcome_email(email, org_name, api_key, org_id)
    if email_sent:
        message = f"Organisation '{org_name}' created. Welcome email sent to {email}."
    else:
        message = f"Organisation '{org_name}' created. Save your API key — it will not be shown again."
    return OrgRegistrationResponse(
        org_id=org_id,
        api_key=api_key,
        dashboard_url=dashboard_url,
        message=message
    )


@app.get("/org/context")
async def org_context(request: Request) -> Dict[str, Any]:
    """Return the tenant identity resolved from the caller's verified API key."""
    org_id = await get_org_id_for_request(request)
    return {"org_id": org_id}


@app.get("/orgs")
async def list_orgs(_admin: None = Depends(require_admin)):
    try:
        headers = {
            "apikey": supabase_audit_client.key or "",
            "authorization": f"Bearer {supabase_audit_client.key}",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{supabase_audit_client.url}/rest/v1/orgs",
                headers=headers,
                params={"select": "org_id,name,email,active,created_at", "order": "created_at.desc"},
            )
            resp.raise_for_status()
            data = resp.json()
        return {"orgs": data, "count": len(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to retrieve organisations")

async def get_org_from_request(request: Request) -> str:
    """Return a verified tenant ID; never silently fall back after a cache miss."""
    return await get_org_id_for_request(request)

# ══════════════════════════════════════════════════════════════
# PHASE 12 — INCIDENT REPLAY ENGINE
# ══════════════════════════════════════════════════════════════

def _compute_replay_bdi_band(bdi_score: float) -> str:
    if bdi_score is None:
        return "UNKNOWN"
    if bdi_score >= 0.85:
        return "CRITICAL"
    if bdi_score >= 0.65:
        return "HIGH"
    if bdi_score >= 0.40:
        return "ELEVATED"
    return "STABLE"


def _compute_replay_entropy_band(entropy: float) -> str:
    if entropy is None:
        return "UNKNOWN"
    if entropy >= 0.85:
        return "CRITICAL"
    if entropy >= 0.65:
        return "HIGH"
    if entropy >= 0.40:
        return "ELEVATED"
    return "STABLE"


def _build_replay_step(event: dict, turn_index: int) -> dict:
    bdi = event.get("bdi_score")
    entropy = event.get("entropy")
    bdi_band = _compute_replay_bdi_band(bdi)
    entropy_band = _compute_replay_entropy_band(entropy)
    drift_flagged = bdi_band in ("HIGH", "CRITICAL") or entropy_band in ("HIGH", "CRITICAL")
    return {
        "turn": turn_index + 1,
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "agent_id": event.get("agent_id"),
        "session_id": event.get("session_id"),
        "action": event.get("action", "intercept"),
        "status": event.get("status", "unknown"),
        "jurisdiction": event.get("jurisdiction"),
        "bdi_score": bdi,
        "bdi_band": bdi_band,
        "entropy": entropy,
        "entropy_band": entropy_band,
        "drift_flagged": drift_flagged,
        "input_preview": (event.get("input_text") or "")[:200],
        "output_preview": (event.get("output_text") or "")[:200],
        "row_hash_present": bool(event.get("row_hash")),
        "row_hash_valid": verify_ai_event_row(event),
        "chain_link_present": bool(event.get("prev_hash")),
        "raw": event,
    }


@app.post("/replay/flag")
async def flag_session_for_replay_endpoint(
    request: Request,
    _operator: Dict[str, str] = Depends(require_operator),
    session_id: str = Body(..., embed=True),
    trigger_reason: str = Body("manual", embed=True),
    flagged_by: str = Body("dashboard", embed=True),
):
    org_id = await get_org_from_request(request)
    from audit import flag_session_for_replay
    record = await flag_session_for_replay(
        session_id=session_id,
        org_id=org_id,
        trigger_reason=trigger_reason,
        flagged_by=flagged_by,
    )
    return {
        "status": "flagged",
        "session_id": session_id,
        "org_id": org_id,
        "trigger_reason": trigger_reason,
        "record": record,
        "_readonly_note": "Flagging does not modify live session state.",
    }


@app.get("/replay")
async def list_replay_sessions(
    request: Request,
    status: str = Query(None),
):
    org_id = await get_org_from_request(request)
    from audit import get_replay_sessions
    sessions = await get_replay_sessions(org_id=org_id, status=status)
    return {
        "org_id": org_id,
        "count": len(sessions),
        "status_filter": status,
        "sessions": sessions,
    }


@app.get("/replay/{session_id}")
async def get_session_replay(
    session_id: str,
    request: Request,
    raw: bool = Query(False),
):
    org_id = await get_org_from_request(request)
    from audit import get_replay_session_events
    events = await get_replay_session_events(session_id=session_id, org_id=org_id)
    if not events:
        raise HTTPException(
            status_code=404,
            detail=f"No events found for session '{session_id}' in org '{org_id}'.",
        )
    steps = [_build_replay_step(ev, i) for i, ev in enumerate(events)]
    bdi_scores = [s["bdi_score"] for s in steps if s["bdi_score"] is not None]
    entropies = [s["entropy"] for s in steps if s["entropy"] is not None]
    drift_flags = [s for s in steps if s["drift_flagged"]]
    bdi_trajectory = "stable"
    if len(bdi_scores) >= 2:
        if bdi_scores[-1] > bdi_scores[0] + 0.20:
            bdi_trajectory = "escalating"
        elif bdi_scores[-1] < bdi_scores[0] - 0.20:
            bdi_trajectory = "de-escalating"
    jurisdiction = next((s["jurisdiction"] for s in steps if s.get("jurisdiction")), "UNKNOWN")
    summary = {
        "session_id": session_id,
        "org_id": org_id,
        "jurisdiction": jurisdiction,
        "total_turns": len(steps),
        "drift_flagged_turns": len(drift_flags),
        "bdi_peak": round(max(bdi_scores), 4) if bdi_scores else None,
        "bdi_start": round(bdi_scores[0], 4) if bdi_scores else None,
        "bdi_end": round(bdi_scores[-1], 4) if bdi_scores else None,
        "bdi_trajectory": bdi_trajectory,
        "entropy_peak": round(max(entropies), 4) if entropies else None,
        "entropy_avg": round(sum(entropies) / len(entropies), 4) if entropies else None,
        "hash_chain_status": (
            "TAMPERED" if any(s["row_hash_present"] and not s["row_hash_valid"] for s in steps)
            else "PARTIAL" if all(s["row_hash_present"] and s["row_hash_valid"] for s in steps)
            else "UNAVAILABLE"
        ),
        "hash_chain_note": "Row hashes are recomputed for this session. The complete chain and an external anchor are not verified here.",
        "first_event_at": steps[0]["timestamp"] if steps else None,
        "last_event_at": steps[-1]["timestamp"] if steps else None,
        "_readonly": True,
        "_isolation": "org_scoped — cross-org replay blocked at DB query level",
    }
    if raw:
        return {"summary": summary, "events_raw": events}
    return {"summary": summary, "action_chain": steps}


@app.post("/replay/{session_id}/mark-reviewed")
async def mark_replay_session_reviewed(
    session_id: str,
    request: Request,
    _operator: Dict[str, str] = Depends(require_operator),
    reviewed_by: str = Body("dashboard", embed=True),
    notes: str = Body("", embed=True),
):
    org_id = await get_org_from_request(request)
    from audit import mark_replay_reviewed
    success = await mark_replay_reviewed(
        session_id=session_id,
        org_id=org_id,
        reviewed_by=reviewed_by,
        notes=notes,
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to mark session as reviewed.")
    return {
        "status": "reviewed",
        "session_id": session_id,
        "org_id": org_id,
        "reviewed_by": reviewed_by,
        "notes": notes,
    }

