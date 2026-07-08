"""
webhook_engine.py — Phase 7 Stage 2: Webhook Alerts

Fires signed JSON payloads to registered webhook URLs whenever a legal hold
is auto-opened by the Pulse governance engine. Compatible with Slack incoming
webhooks, PagerDuty Events API v2, Microsoft Teams connectors, and any SIEM
that accepts HTTP POST.

Signing: HMAC-SHA256 over the raw JSON body, delivered as the
X-Pulse-Signature header (format: sha256=<hex_digest>). Receivers should
verify this before trusting the payload.

Retry logic: 3 attempts with exponential backoff (1s, 2s, 4s). Failures are
logged but never raise — a webhook delivery failure must never block the
governance engine or the /intercept response.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT = 10.0      # seconds per attempt
WEBHOOK_MAX_RETRIES = 3
WEBHOOK_RETRY_BASE = 1.0    # seconds — doubles each retry


def _sign_payload(secret: str, body: bytes) -> str:
    """Return sha256=<hex> HMAC signature over the raw body bytes."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _build_payload(hold: Dict[str, Any], event_type: str = "legal_hold.opened") -> Dict[str, Any]:
    """Build the canonical webhook payload from a legal hold dict."""
    return {
        "event": event_type,
        "fired_at": datetime.now(timezone.utc).isoformat(),
        "pulse_version": "7.2",
        "hold": {
            "id": hold.get("id"),
            "trigger_type": hold.get("trigger_type"),
            "severity": hold.get("severity"),
            "reason": hold.get("reason"),
            "status": hold.get("status"),
            "agent_id": hold.get("agent_id"),
            "session_id": hold.get("session_id"),
            "framework": hold.get("framework"),
            "jurisdiction": hold.get("jurisdiction"),
            "created_at": hold.get("created_at"),
        },
    }


async def _deliver_once(
    client: httpx.AsyncClient,
    url: str,
    body: bytes,
    signature: str,
) -> bool:
    """Attempt a single delivery. Returns True on 2xx, False otherwise."""
    try:
        response = await client.post(
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Pulse-Signature": signature,
                "X-Pulse-Event": "legal_hold.opened",
                "User-Agent": "Pulse-Webhook/7.2",
            },
            timeout=WEBHOOK_TIMEOUT,
        )
        if response.status_code < 300:
            return True
        logger.warning(
            "Webhook delivery non-2xx: url=%s status=%d body=%s",
            url, response.status_code, response.text[:200],
        )
        return False
    except httpx.HTTPError as exc:
        logger.warning("Webhook delivery error: url=%s error=%s", url, exc)
        return False


async def _deliver_with_retry(
    url: str,
    secret: str,
    hold: Dict[str, Any],
) -> bool:
    """Deliver with exponential backoff. Returns True if any attempt succeeded."""
    payload = _build_payload(hold)
    body = json.dumps(payload, default=str).encode()
    signature = _sign_payload(secret, body)

    async with httpx.AsyncClient() as client:
        for attempt in range(1, WEBHOOK_MAX_RETRIES + 1):
            success = await _deliver_once(client, url, body, signature)
            if success:
                logger.info(
                    "Webhook delivered: url=%s hold_id=%s attempt=%d",
                    url, hold.get("id"), attempt,
                )
                return True
            if attempt < WEBHOOK_MAX_RETRIES:
                wait = WEBHOOK_RETRY_BASE * (2 ** (attempt - 1))
                logger.info(
                    "Webhook retry %d/%d in %.1fs: url=%s",
                    attempt, WEBHOOK_MAX_RETRIES, wait, url,
                )
                await asyncio.sleep(wait)

    logger.error(
        "Webhook delivery failed after %d attempts: url=%s hold_id=%s",
        WEBHOOK_MAX_RETRIES, url, hold.get("id"),
    )
    return False


async def fire_webhooks(
    hold: Dict[str, Any],
    registrations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Fire webhooks for all active registrations matching this hold's event type.
    Returns a list of delivery result dicts (one per registration attempted).
    Never raises — all errors are caught and logged.
    """
    if not hold or not registrations:
        return []

    results: List[Dict[str, Any]] = []

    for reg in registrations:
        if not reg.get("active", True):
            continue
        events = reg.get("events") or ["legal_hold.opened"]
        if "legal_hold.opened" not in events:
            continue

        url = reg.get("url", "")
        secret = reg.get("secret", "")
        reg_id = reg.get("id", "unknown")

        if not url or not secret:
            logger.warning("Skipping webhook %s: missing url or secret", reg_id)
            continue

        try:
            success = await _deliver_with_retry(url, secret, hold)
        except Exception as exc:
            logger.error("Unexpected webhook error: reg_id=%s error=%s", reg_id, exc)
            success = False

        results.append({
            "webhook_id": reg_id,
            "org_id": reg.get("org_id"),
            "url": url,
            "delivered": success,
            "hold_id": hold.get("id"),
            "fired_at": datetime.now(timezone.utc).isoformat(),
        })

    return results
