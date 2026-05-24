from __future__ import annotations

import json
import threading
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional


class ComplianceEventStore:
    """Thread-safe store of policy-blocked events with regulatory tags."""

    def __init__(self, max_events: int = 2000) -> None:
        self._events: Deque[Dict[str, Any]] = deque(maxlen=max_events)
        self._lock = threading.RLock()

    def record_blocked(self, evaluation: Dict[str, Any], *, agent_id: Optional[str] = None) -> Dict[str, Any]:
        event = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "decision": "blocked",
            "allowed": False,
            **evaluation,
        }
        with self._lock:
            self._events.append(event)
        return event

    def list_blocked(self, limit: int = 500) -> List[Dict[str, Any]]:
        with self._lock:
            blocked = [event for event in self._events if not event.get("allowed", True)]
            return list(blocked)[-limit:]

    def export_report(self, *, limit: int = 500) -> Dict[str, Any]:
        """Compile tagged blocked events into a compliance report."""
        events = self.list_blocked(limit=limit)
        framework_counter: Counter[str] = Counter()
        violation_counter: Counter[str] = Counter()
        agent_counter: Counter[str] = Counter()

        tagged_events: List[Dict[str, Any]] = []
        for event in events:
            frameworks = event.get("regulatory_frameworks") or []
            violation = event.get("violation_type") or "unknown"
            agent = event.get("agent_id") or "__anonymous__"

            for framework in frameworks:
                framework_counter[str(framework)] += 1
            violation_counter[str(violation)] += 1
            agent_counter[str(agent)] += 1

            tagged_events.append(
                {
                    "recorded_at": event.get("recorded_at"),
                    "agent_id": agent,
                    "operation": event.get("operation"),
                    "violation_type": violation,
                    "risk_level": event.get("risk_level"),
                    "reason": event.get("reason"),
                    "regulatory_frameworks": list(frameworks),
                }
            )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_blocked_events": len(tagged_events),
                "by_framework": dict(framework_counter),
                "by_violation_type": dict(violation_counter),
                "by_agent": dict(agent_counter),
            },
            "frameworks_tracked": ["EU AI Act", "GDPR", "SOC2", "ISO 42001"],
            "events": tagged_events,
        }

    def export_json(self, *, limit: int = 500, indent: int = 2) -> str:
        return json.dumps(self.export_report(limit=limit), indent=indent)

    def export_markdown(self, *, limit: int = 500) -> str:
        report = self.export_report(limit=limit)
        lines = [
            "# Pulse Governance — Compliance Report",
            "",
            f"**Generated:** {report['generated_at']}",
            f"**Blocked events:** {report['summary']['total_blocked_events']}",
            "",
            "## Summary by Framework",
            "",
        ]
        for framework, count in sorted(report["summary"]["by_framework"].items()):
            lines.append(f"- **{framework}:** {count} violation(s)")
        lines.extend(["", "## Summary by Violation Type", ""])
        for violation, count in sorted(report["summary"]["by_violation_type"].items()):
            lines.append(f"- `{violation}`: {count}")
        lines.extend(["", "## Tagged Events", ""])
        for event in report["events"]:
            frameworks = ", ".join(event.get("regulatory_frameworks") or [])
            lines.append(
                f"- **{event.get('recorded_at')}** | agent `{event.get('agent_id')}` | "
                f"`{event.get('operation')}` | {event.get('violation_type')} | [{frameworks}]"
            )
        lines.append("")
        return "\n".join(lines)


compliance_store = ComplianceEventStore()
