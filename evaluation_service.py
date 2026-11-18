"""Deterministic, configurable evaluators for versioned offline model datasets."""
from __future__ import annotations

import json
from typing import Any, Dict


SUPPORTED_EVALUATORS = {"exact_match", "contains", "not_contains", "contains_any", "json_field_equals"}


def evaluate_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a supplied candidate output without executing user code or regexes."""
    case_id = str(case["case_id"])
    evaluator = str(case["evaluator"])
    actual = case.get("candidate_output", "")
    expected = case.get("expected")
    passed = False
    reason = ""

    if evaluator == "exact_match":
        passed = isinstance(actual, str) and isinstance(expected, str) and actual.strip() == expected.strip()
        reason = "Output matches expected text." if passed else "Output differs from expected text."
    elif evaluator == "contains":
        passed = isinstance(actual, str) and isinstance(expected, str) and expected.casefold() in actual.casefold()
        reason = "Output contains the required text." if passed else "Required text is missing."
    elif evaluator == "not_contains":
        passed = isinstance(actual, str) and isinstance(expected, str) and expected.casefold() not in actual.casefold()
        reason = "Prohibited text is absent." if passed else "Prohibited text was found."
    elif evaluator == "contains_any":
        options = expected if isinstance(expected, list) else []
        passed = isinstance(actual, str) and any(isinstance(item, str) and item.casefold() in actual.casefold() for item in options)
        reason = "Output contains an accepted alternative." if passed else "No accepted alternative was found."
    elif evaluator == "json_field_equals":
        field = case.get("field")
        try:
            parsed = json.loads(actual) if isinstance(actual, str) else actual
            value = parsed
            for part in str(field or "").split("."):
                value = value[part] if isinstance(value, dict) else None
            passed = value == expected
            reason = "JSON field matches expected value." if passed else "JSON field does not match expected value."
        except (json.JSONDecodeError, TypeError, KeyError):
            reason = "Candidate output is not valid JSON or the field is missing."
    else:
        raise ValueError(f"Unsupported evaluator: {evaluator}")

    return {"case_id": case_id, "evaluator": evaluator, "passed": bool(passed), "score": 1.0 if passed else 0.0, "reason": reason}
