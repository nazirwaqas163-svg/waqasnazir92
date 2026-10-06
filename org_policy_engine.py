# org_policy_engine.py
# Phase 6 Stage 2 — Custom Org Policy Enforcement
# Loads org policies from Supabase and checks agent input/output against them.
#
# FP-2 patch: keyword rules no longer use bare substring matching.
#   - Known PII keywords (email, phone, nric, credit_card ...) match the actual
#     data pattern (an address, a number), not the word that names it.
#   - Every other keyword matches as a whole word/phrase (underscores = spaces),
#     so "phone" no longer fires inside "telephone" and field names still match.
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

# Cache: org_id -> {"policies": [...], "ts": float}
_policy_cache: Dict[str, Dict[str, Any]] = {}
POLICY_CACHE_TTL = 60.0  # seconds

# Keyword -> regex that matches real data of that kind.
_PII_PATTERNS: Dict[str, re.Pattern] = {
    "email": re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I),
    "email_address": re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I),
    # +60 12-345 6789 / 012-3456789 / 03-1234 5678. Digit runs glued to letters or
    # hyphens (AP-20260708-0042, INV-2026-0042) are reference IDs, not PII.
    "phone": re.compile(r"(?<![\w\-])(?:\+?\d[\s\-()]?){9,14}\d(?![\w\-])"),
    "phone_number": re.compile(r"(?<![\w\-])(?:\+?\d[\s\-()]?){9,14}\d(?![\w\-])"),
    "mobile": re.compile(r"(?<![\w\-])(?:\+?\d[\s\-()]?){9,14}\d(?![\w\-])"),
    # Malaysian NRIC: YYMMDD-PB-###G
    "nric": re.compile(r"(?<![\w\-])\d{6}-?\d{2}-?\d{4}(?![\w\-])"),
    "ic_number": re.compile(r"(?<![\w\-])\d{6}-?\d{2}-?\d{4}(?![\w\-])"),
    "credit_card": re.compile(r"(?<![\w\-])(?:\d[ \-]?){13,18}\d(?![\w\-])"),
    "card_number": re.compile(r"(?<![\w\-])(?:\d[ \-]?){13,18}\d(?![\w\-])"),
}


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
    """Load active policies for an org. Uses 60s in-memory cache."""
    cached = _cache_get(org_id)
    if cached is not None:
        return cached
    policies = await supabase_client.list_org_policies(org_id=org_id)
    _cache_set(org_id, policies)
    return policies


def _keyword_hit(keyword: str, text: str) -> bool:
    """True if `keyword` genuinely appears in `text` (see FP-2 note above)."""
    kw = (keyword or "").strip().lower()
    if not kw or not text:
        return False
    key = kw.replace(" ", "_")
    pattern = _PII_PATTERNS.get(key)
    if pattern is not None:
        return pattern.search(text) is not None
    # Whole word / phrase; underscore and space are interchangeable.
    phrase = r"[\s_]+".join(re.escape(part) for part in re.split(r"[\s_]+", kw) if part)
    return re.search(rf"(?<![a-z0-9]){phrase}(?![a-z0-9])", text, re.I) is not None


def _check_rule(rule: Dict[str, Any], input_text: str, output_text: str) -> bool:
    """Evaluate a single rule dict against input/output text."""
    field = rule.get("field", "output")
    match_str = (rule.get("match") or rule.get("keyword") or "").strip()
    if not match_str:
        return False
    target = output_text if field == "output" else input_text
    return _keyword_hit(match_str, target or "")


def check_policy(
    input_text: str,
    output_text: str,
    policy: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Check a single policy against input/output text.
    Supports both rule formats:
      - New: rules is a list of {type, field, match, action}
      - Legacy: rules is a dict with {keywords, threshold, severity, action}
    Returns a violation dict or None.
    """
    rules = policy.get("rules") or []

    matched_keywords: List[str] = []
    final_action = "flag"

    # New format: rules is a list
    if isinstance(rules, list):
        for rule in rules:
            if _check_rule(rule, input_text, output_text):
                matched_keywords.append(rule.get("match") or rule.get("keyword") or "")
                # block takes priority over flag
                if rule.get("action") == "block":
                    final_action = "block"

    # Legacy format: rules is a dict with keywords list
    elif isinstance(rules, dict):
        keywords = rules.get("keywords") or []
        threshold = int(rules.get("threshold", 1))
        combined = f"{input_text or ''} {output_text or ''}"
        matched_keywords = [kw for kw in keywords if _keyword_hit(kw, combined)]
        if len(matched_keywords) < threshold:
            matched_keywords = []
        final_action = rules.get("action", "flag")

    if not matched_keywords:
        return None

    return {
        "policy_id": policy.get("policy_id"),
        "policy_name": policy.get("name"),
        "severity": "high" if final_action == "block" else "medium",
        "action": final_action,
        "matched_keywords": matched_keywords,
        "org_id": policy.get("org_id"),
    }


async def evaluate_org_policies(
    input_text: str,
    output_text: str,
    org_id: str,
    supabase_client: Any,
) -> List[Dict[str, Any]]:
    """Load and evaluate all active org policies against input and output text."""
    policies = await load_policies(org_id, supabase_client)
    violations = []
    for policy in policies:
        violation = check_policy(input_text, output_text, policy)
        if violation:
            violations.append(violation)
    return violations
