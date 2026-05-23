from __future__ import annotations

from dataclasses import dataclass
from typing import Final

BLOCKED_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"DELETE", "EXPORT", "WRITE_EXTERNAL", "QUERY_ALL"}
)

ALLOWED_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"READ", "QUERY", "STATUS", "WRITE_INTERNAL", "PING"}
)


@dataclass(frozen=True)
class PolicyEvaluation:
    allowed: bool
    reason: str
    risk_level: str

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "risk_level": self.risk_level,
        }


def evaluate_tool_call(operation: str | None) -> PolicyEvaluation:
    normalized = (operation or "").strip().upper()
    if not normalized:
        return PolicyEvaluation(
            allowed=False,
            reason="No operation specified; deny-by-default policy applies.",
            risk_level="high",
        )

    if normalized in BLOCKED_OPERATIONS:
        return PolicyEvaluation(
            allowed=False,
            reason=f"Operation '{normalized}' is blocked by governance policy.",
            risk_level="critical",
        )

    if normalized in ALLOWED_OPERATIONS:
        return PolicyEvaluation(
            allowed=True,
            reason=f"Operation '{normalized}' is on the allowlist.",
            risk_level="low",
        )

    return PolicyEvaluation(
        allowed=False,
        reason=f"Operation '{normalized}' is not on the allowlist; deny-by-default policy applies.",
        risk_level="medium",
    )
