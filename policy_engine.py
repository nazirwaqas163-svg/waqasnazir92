from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, List, Optional, Tuple

BLOCKED_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"DELETE", "EXPORT", "WRITE_EXTERNAL", "QUERY_ALL"}
)

ALLOWED_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"READ", "QUERY", "STATUS", "WRITE_INTERNAL", "PING"}
)

# ASEAN regulatory frameworks referenced in compliance exports.
FRAMEWORK_PDPA_MY: Final[str] = "PDPA Malaysia"
FRAMEWORK_PDPA_TH: Final[str] = "PDPA Thailand"
FRAMEWORK_PDPC_SG: Final[str] = "PDPC Singapore"
FRAMEWORK_MGF_SG: Final[str] = "MAS Model AI Governance Framework"
FRAMEWORK_VIETNAM_AI: Final[str] = "Vietnam AI Law 2024"
FRAMEWORK_ISO_42001: Final[str] = "ISO 42001"

VIOLATION_REGULATORY_TAGS: Final[dict[str, Tuple[str, ...]]] = {
    "missing_operation": (FRAMEWORK_PDPA_MY, FRAMEWORK_PDPC_SG, FRAMEWORK_ISO_42001),
    "blocked_delete": (FRAMEWORK_PDPA_MY, FRAMEWORK_PDPA_TH, FRAMEWORK_MGF_SG, FRAMEWORK_ISO_42001),
    "blocked_export": (FRAMEWORK_PDPA_MY, FRAMEWORK_PDPC_SG, FRAMEWORK_VIETNAM_AI, FRAMEWORK_MGF_SG),
    "blocked_write_external": (FRAMEWORK_PDPA_MY, FRAMEWORK_PDPC_SG, FRAMEWORK_MGF_SG, FRAMEWORK_VIETNAM_AI),
    "blocked_query_all": (FRAMEWORK_PDPA_MY, FRAMEWORK_PDPA_TH, FRAMEWORK_ISO_42001, FRAMEWORK_MGF_SG),
    "deny_by_default": (FRAMEWORK_MGF_SG, FRAMEWORK_ISO_42001, FRAMEWORK_PDPA_MY),
    "unknown_operation": (FRAMEWORK_MGF_SG, FRAMEWORK_ISO_42001),
}


@dataclass(frozen=True)
class PolicyEvaluation:
    allowed: bool
    reason: str
    risk_level: str
    violation_type: Optional[str] = None
    regulatory_frameworks: Tuple[str, ...] = field(default_factory=tuple)
    operation: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "allowed": self.allowed,
            "reason": self.reason,
            "risk_level": self.risk_level,
        }
        if not self.allowed:
            payload["violation_type"] = self.violation_type
            payload["regulatory_frameworks"] = list(self.regulatory_frameworks)
        if self.operation is not None:
            payload["operation"] = self.operation
        return payload


def _blocked_evaluation(
    *,
    operation: str,
    violation_type: str,
    reason: str,
    risk_level: str,
) -> PolicyEvaluation:
    frameworks = VIOLATION_REGULATORY_TAGS.get(violation_type, (FRAMEWORK_MGF_SG, FRAMEWORK_ISO_42001))
    return PolicyEvaluation(
        allowed=False,
        reason=reason,
        risk_level=risk_level,
        violation_type=violation_type,
        regulatory_frameworks=frameworks,
        operation=operation,
    )


def evaluate_tool_call(operation: str | None) -> PolicyEvaluation:
    normalized = (operation or "").strip().upper()
    if not normalized:
        return _blocked_evaluation(
            operation="",
            violation_type="missing_operation",
            reason="No operation specified; deny-by-default policy applies.",
            risk_level="high",
        )

    if normalized == "DELETE":
        return _blocked_evaluation(
            operation=normalized,
            violation_type="blocked_delete",
            reason=f"Operation '{normalized}' is blocked by governance policy.",
            risk_level="critical",
        )

    if normalized == "EXPORT":
        return _blocked_evaluation(
            operation=normalized,
            violation_type="blocked_export",
            reason=f"Operation '{normalized}' is blocked by governance policy.",
            risk_level="critical",
        )

    if normalized == "WRITE_EXTERNAL":
        return _blocked_evaluation(
            operation=normalized,
            violation_type="blocked_write_external",
            reason=f"Operation '{normalized}' is blocked by governance policy.",
            risk_level="critical",
        )

    if normalized == "QUERY_ALL":
        return _blocked_evaluation(
            operation=normalized,
            violation_type="blocked_query_all",
            reason=f"Operation '{normalized}' is blocked by governance policy.",
            risk_level="critical",
        )

    if normalized in ALLOWED_OPERATIONS:
        return PolicyEvaluation(
            allowed=True,
            reason=f"Operation '{normalized}' is on the allowlist.",
            risk_level="low",
            operation=normalized,
        )

    return _blocked_evaluation(
        operation=normalized,
        violation_type="deny_by_default",
        reason=f"Operation '{normalized}' is not on the allowlist; deny-by-default policy applies.",
        risk_level="medium",
    )
