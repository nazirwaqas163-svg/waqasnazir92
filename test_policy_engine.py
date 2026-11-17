"""Regression checks for expected safe and blocked tool operations."""

from policy_engine import evaluate_tool_call


def test_normal_operations_are_allowed() -> None:
    # These routine operations are explicitly supported by the app.
    for operation in ("READ", "QUERY", "STATUS", "WRITE_INTERNAL", "PING"):
        result = evaluate_tool_call(operation)
        assert result.allowed, f"{operation} should not be a false positive"


def test_case_and_surrounding_whitespace_do_not_block_normal_operations() -> None:
    for operation in (" read ", "Query", " status "):
        result = evaluate_tool_call(operation)
        assert result.allowed, f"{operation!r} should normalize to an allowed operation"


def test_dangerous_operations_are_blocked() -> None:
    for operation in ("DELETE", "EXPORT", "WRITE_EXTERNAL", "QUERY_ALL"):
        result = evaluate_tool_call(operation)
        assert not result.allowed, f"{operation} should be blocked"
        assert result.risk_level == "critical"


def test_unknown_operations_remain_denied_by_default() -> None:
    result = evaluate_tool_call("UNKNOWN_OPERATION")
    assert not result.allowed
    assert result.violation_type == "deny_by_default"
