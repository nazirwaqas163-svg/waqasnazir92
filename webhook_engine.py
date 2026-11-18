"""Signed webhook delivery with bounded retries and idempotency headers."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)
WEBHOOK_TIMEOUT = 10.0
WEBHOOK_MAX_RETRIES = 3
WEBHOOK_RETRY_BASE = 1.0


def _sign_payload(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _build_payload(payload: Dict[str, Any], event_type: str, delivery_id: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "event": event_type,
        "fired_at": datetime.now(timezone.utc).isoformat(),
        "pulse_version": "7.2",
        "delivery_id": delivery_id,
    }
    if event_type == "legal_hold.opened":
        result["hold"] = {
            key: payload.get(key)
            for key in (
                "id", "trigger_type", "severity", "reason", "status", "agent_id",
                "session_id", "framework", "jurisdiction", "created_at",
            )
        }
    else:
        result["data"] = payload
    return result


async def _deliver_once(
    client: httpx.AsyncClient,
    url: str,
    body: bytes,
    signature: str,
    event_type: str,
    delivery_id: str,
) -> Tuple[bool, Optional[int], Optional[str]]:
    try:
        response = await client.post(
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Pulse-Signature": signature,
                "X-Pulse-Event": event_type,
                "X-Pulse-Delivery-ID": delivery_id,
                "User-Agent": "Pulse-Webhook/7.2",
            },
            timeout=WEBHOOK_TIMEOUT,
        )
        return response.status_code < 300, response.status_code, None if response.status_code < 300 else f"http_{response.status_code}"
    except httpx.HTTPError as exc:
        logger.warning("Webhook delivery transport failed: type=%s", type(exc).__name__)
        return False, None, type(exc).__name__


async def _deliver_with_retry(
    *,
    url: str,
    secret: str,
    payload: Dict[str, Any],
    event_type: str,
    delivery_id: str,
) -> Dict[str, Any]:
    body = json.dumps(_build_payload(payload, event_type, delivery_id), default=str).encode()
    signature = _sign_payload(secret, body)
    attempts = 0
    response_status: Optional[int] = None
    error: Optional[str] = None
    async with httpx.AsyncClient() as client:
        for attempt in range(1, WEBHOOK_MAX_RETRIES + 1):
            attempts = attempt
            delivered, response_status, error = await _deliver_once(
                client, url, body, signature, event_type, delivery_id
            )
            if delivered:
                return {
                    "delivered": True, "attempts": attempts,
                    "response_status": response_status, "error": None,
                }
            if attempt < WEBHOOK_MAX_RETRIES:
                await asyncio.sleep(WEBHOOK_RETRY_BASE * (2 ** (attempt - 1)))
    return {
        "delivered": False, "attempts": attempts,
        "response_status": response_status, "error": error or "delivery_failed",
    }


async def fire_webhooks(
    payload: Dict[str, Any],
    registrations: List[Dict[str, Any]],
    *,
    event_type: str = "legal_hold.opened",
    delivery_keys: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Send one signed event to registrations subscribed to its event type."""
    results: List[Dict[str, Any]] = []
    if not payload or not registrations:
        return results
    keys = delivery_keys or {}
    for registration in registrations:
        if not registration.get("active", True):
            continue
        events = registration.get("events") or ["legal_hold.opened"]
        if event_type not in events:
            continue
        registration_id = str(registration.get("id", "unknown"))
        url = registration.get("url", "")
        secret = registration.get("secret", "")
        delivery_id = keys.get(registration_id) or hashlib.sha256(
            f"{event_type}:{payload.get('id', payload.get('run_id', 'event'))}:{registration_id}".encode()
        ).hexdigest()
        if not url or not secret:
            results.append({
                "registration_id": registration_id, "delivery_id": delivery_id,
                "delivered": False, "attempts": 0, "error": "missing_url_or_secret",
            })
            continue
        try:
            outcome = await _deliver_with_retry(
                url=url, secret=secret, payload=payload,
                event_type=event_type, delivery_id=delivery_id,
            )
            results.append({
                "registration_id": registration_id,
                "delivery_id": delivery_id,
                **outcome,
            })
        except Exception as exc:
            logger.exception("Unexpected webhook delivery failure: registration_id=%s", registration_id)
            results.append({
                "registration_id": registration_id, "delivery_id": delivery_id,
                "delivered": False, "attempts": 0, "error": type(exc).__name__,
            })
    return results
