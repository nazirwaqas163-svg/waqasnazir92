# org_policy_engine.py
# Phase 6 Stage 2 — Custom Org Policy Enforcement
# Loads org policies from Supabase and checks agent input against them.

from __future__ import annotations
import time
from typing import Any, Dict, List, Optional

# Cache: org_id -> {"policies": [...], "ts": float}
_policy_cache: Dict[str, Dict[str, Any]] = {}
POLICY_CACHE_TTL = 60.0  # seconds


def _cache_get(org_id: str) -> Optional[List[Dict[str, Any]]]:
    entry = _policy_cache.get(org_id)
    if entry is None:
        return None
    if time.monotonic() - entry["ts"] > POLICY_CACHE_TTL:
        _policy_cache.pop(org_id, None)
        return None
    return entry["policies"]


def _cache_set(org_id: str, policies: List[Dict[str, Any]]) -> None:
    _policy_cache[org_id] = {"policies": policies, "ts": time.monotonic()}


async def load_policies(org_id: str, supabase_client: Any) -> List[Dict[str, Any]]:
    """Load active policies for an org. Uses 60s cache."""
    cached = _cache_get(org_id)
    if cached is not None:
        return cached
    policies = await supabase_client.list_org_policies(org_id=org_id)
    _cache_set(org_id, policies)
    return policies


def check_policy(input_text: str, policy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Check a single policy against input text. Returns a violation dict or None."""
    rules = policy.get("rules") or {}
    keywords = rules.get("keywords") or []
    threshold = int(rules.get("threshold", 1))

    if not keywords:
        return None

    lowered = input_text.lower()
    matched = [kw for kw in keywords if kw.lower() in lowered]

    if len(matched) >= threshold:
        return {
            "policy_id": policy.get("policy_id"),
            "policy_name": policy.get("name"),
            "severity": rules.get("severity", "medium"),
            "action": rules.get("action", "alert"),
            "matched_keywords": matched,
            "org_id": policy.get("org_id"),
        }
    return None


async def evaluate_org_policies(
    input_text: str,
    org_id: str,
    supabase_client: Any,
) -> List[Dict[str, Any]]:
    """Load and evaluate all active org policies against input text."""
    policies = await load_policies(org_id, supabase_client)
    violations = []
    for policy in policies:
        violation = check_policy(input_text, policy)
        if violation:
            violations.append(violation)
    return violations
