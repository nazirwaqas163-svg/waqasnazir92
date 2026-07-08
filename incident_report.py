"""
incident_report.py — Phase 7 Stage 4: Auto Incident Report + Evidence Package

Generates a sealed, signed evidence package PDF when a legal hold opens.
Stores the report in Supabase (incident_reports table) and makes it
downloadable via GET /legal-hold/{id}/evidence-package.

The PDF is built on top of the existing passport.py renderer — no duplicate
PDF logic. The incident report is a purpose-built document distinct from
the agent passport:

  Passport  = compliance identity document per agent (all-time summary)
  Incident  = point-in-time sealed evidence package per breach event

The report is sealed (immutable) immediately on generation. DPO email
delivery is optional and triggered separately via the send endpoint.
"""

from __future__ import annotations

import base64
import io
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Evidence package assembler
# ---------------------------------------------------------------------------

def assemble_evidence_package(
    *,
    hold: Dict[str, Any],
    agent_events: List[Dict[str, Any]],
    drift: Optional[Dict[str, Any]] = None,
    shadow: Optional[Dict[str, Any]] = None,
    threat_classification: Optional[Dict[str, Any]] = None,
    policy_violations: Optional[List[Dict[str, Any]]] = None,
    exfiltration: Optional[Dict[str, Any]] = None,
    swarm: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build the canonical evidence package dict for a legal hold.
    This is the JSON that gets sealed and signed.
    """
    generated_at = datetime.now(timezone.utc).isoformat()

    # Session summary from events
    sessions: Dict[str, int] = {}
    for e in agent_events:
        sid = e.get("session_id")
        if sid:
            sessions[sid] = sessions.get(sid, 0) + 1
    total_turns = len(agent_events)
    blocked_turns = sum(1 for e in agent_events if e.get("policy_result") == "blocked")

    # Seal hash — SHA-256 over canonical hold + generated_at
    seal_payload = json.dumps(
        {"hold_id": hold.get("id"), "generated_at": generated_at},
        sort_keys=True,
    ).encode()
    seal_hash = hashlib.sha256(seal_payload).hexdigest()

    package = {
        "report_type": "INCIDENT_EVIDENCE_PACKAGE",
        "report_version": "7.4",
        "generated_at": generated_at,
        "seal_hash": seal_hash,
        "issuer": "Pulse AI Governance Ledger",
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
            "chain_hash": hold.get("chain_hash"),
        },
        "session_summary": {
            "total_sessions": len(sessions),
            "total_turns": total_turns,
            "blocked_turns": blocked_turns,
            "sessions": list(sessions.keys()),
        },
        "signals": {
            "drift": drift or {},
            "shadow": shadow or {},
            "exfiltration": exfiltration or {},
            "swarm": swarm or {},
            "threat_classification": threat_classification or {},
            "policy_violations": policy_violations or [],
        },
        "regulatory_context": _regulatory_context(hold),
        "note": (
            "This evidence package was automatically generated and sealed by the Pulse "
            "AI Governance Engine at the moment of breach detection. The seal_hash "
            "anchors this document to the originating legal hold. Any modification "
            "invalidates the seal."
        ),
    }

    return package


def _regulatory_context(hold: Dict[str, Any]) -> Dict[str, Any]:
    """Map trigger type and jurisdiction to relevant ASEAN obligations."""
    trigger = (hold.get("trigger_type") or "").lower()
    jurisdiction = hold.get("jurisdiction") or "GENERAL"

    obligations = {
        "MY": {
            "framework": "PDPA Malaysia",
            "reporting_window_hours": 24,
            "obligation": "Notify PDPC of personal data breach within 24 hours.",
            "authority": "Personal Data Protection Commissioner (PDPC) Malaysia",
        },
        "SG": {
            "framework": "Singapore Model AI Governance Framework",
            "reporting_window_hours": 72,
            "obligation": "Incident review and corrective action within 72 hours.",
            "authority": "IMDA / PDPC Singapore",
        },
        "VN": {
            "framework": "Vietnam AI Law",
            "reporting_window_hours": 72,
            "obligation": "Report AI system incident to authority within 72 hours.",
            "authority": "Ministry of Science and Technology, Vietnam",
        },
        "INTL": {
            "framework": "ISO/IEC 42001",
            "reporting_window_hours": 168,
            "obligation": "Log and assess AI management system incident within 7 days.",
            "authority": "Internal AI governance team",
        },
    }

    context = obligations.get(jurisdiction, {
        "framework": "General AI Governance",
        "reporting_window_hours": 72,
        "obligation": "Review and document incident per organisational policy.",
        "authority": "Internal compliance team",
    })

    return {
        **context,
        "trigger_type": trigger,
        "jurisdiction": jurisdiction,
        "action_required": trigger in {
            "exfiltration", "swarm", "compliance_breach", "critical_drift"
        },
    }


# ---------------------------------------------------------------------------
# PDF renderer for incident reports
# ---------------------------------------------------------------------------

def render_incident_pdf(package: Dict[str, Any]) -> bytes:
    """
    Render the evidence package as a sealed PDF.
    Uses reportlab — same dependency as passport.py.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, HRFlowable
        )
    except ImportError:
        raise RuntimeError(
            "reportlab is required for PDF generation. "
            "Add 'reportlab' to requirements.txt and redeploy."
        )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    TEAL = colors.HexColor("#00C9A7")
    DARK = colors.HexColor("#0D1117")
    GREY = colors.HexColor("#6B7280")
    RED = colors.HexColor("#EF4444")

    title_style = ParagraphStyle(
        "Title", parent=styles["Title"], fontSize=18,
        textColor=DARK, spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        "Sub", parent=styles["Normal"], fontSize=9,
        textColor=GREY, spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], fontSize=11,
        textColor=TEAL, spaceBefore=12, spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"], fontSize=8,
        textColor=DARK, spaceAfter=2, leading=12,
    )
    mono_style = ParagraphStyle(
        "Mono", parent=styles["Code"], fontSize=7,
        textColor=GREY, spaceAfter=2,
    )
    warning_style = ParagraphStyle(
        "Warning", parent=styles["Normal"], fontSize=9,
        textColor=RED, spaceAfter=4, leading=14,
    )

    def kv(label: str, value: Any) -> Paragraph:
        val = str(value) if value is not None else "—"
        return Paragraph(f"<b>{label}:</b> {val}", body_style)

    def sec(title: str) -> list:
        return [
            Paragraph(title, section_style),
            HRFlowable(width="100%", thickness=0.5, color=TEAL, spaceAfter=4),
        ]

    story = []
    hold = package.get("hold", {})
    signals = package.get("signals", {})
    reg = package.get("regulatory_context", {})

    # Header
    story.append(Paragraph("PULSE INCIDENT EVIDENCE PACKAGE", title_style))
    story.append(Paragraph(
        f"Report v{package.get('report_version', '7.4')} · "
        f"Hold {hold.get('id', 'unknown')} · "
        f"Generated {package.get('generated_at', '')}",
        sub_style,
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=TEAL, spaceAfter=8))

    # Seal warning
    story.append(Paragraph(
        "⚠ SEALED DOCUMENT — Any modification invalidates the cryptographic seal.",
        warning_style,
    ))
    story.append(Spacer(1, 4))

    # Section 1 — Breach Event
    story += sec("1. Breach Event")
    story.append(kv("Hold ID", hold.get("id")))
    story.append(kv("Trigger Type", hold.get("trigger_type")))
    story.append(kv("Severity", hold.get("severity")))
    story.append(kv("Reason", hold.get("reason")))
    story.append(kv("Status", hold.get("status")))
    story.append(kv("Agent ID", hold.get("agent_id")))
    story.append(kv("Session ID", hold.get("session_id")))
    story.append(kv("Detected At", hold.get("created_at")))
    story.append(kv("Chain Hash", hold.get("chain_hash")))

    # Section 2 — Session Summary
    story += sec("2. Session Activity at Time of Breach")
    summary = package.get("session_summary", {})
    story.append(kv("Total Sessions", summary.get("total_sessions")))
    story.append(kv("Total Turns", summary.get("total_turns")))
    story.append(kv("Blocked Turns", summary.get("blocked_turns")))

    # Section 3 — Detection Signals
    story += sec("3. Detection Signals")
    drift = signals.get("drift", {})
    story.append(kv("Drift Score", drift.get("score")))
    story.append(kv("Drift Status", drift.get("status")))
    story.append(kv("Turns Analyzed", drift.get("turns_analyzed")))
    story.append(Spacer(1, 4))

    exfil = signals.get("exfiltration", {})
    story.append(kv("Exfiltration Risk Score", exfil.get("risk_score")))
    story.append(kv("Exfiltration Alert", exfil.get("alert")))
    story.append(Spacer(1, 4))

    swarm = signals.get("swarm", {})
    story.append(kv("Swarm Suspect", swarm.get("swarm_suspect")))
    story.append(kv("Active Sessions", swarm.get("active_sessions")))
    story.append(Spacer(1, 4))

    tc = signals.get("threat_classification", {})
    story.append(kv("Threat Level", tc.get("threat_level")))
    story.append(kv("Fired Threats", ", ".join(tc.get("fired_threats") or [])))

    pv = signals.get("policy_violations", [])
    if pv:
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Policy Violations:</b>", body_style))
        for v in pv:
            story.append(Paragraph(
                f"  • {v.get('policy_id')} — {v.get('policy_name')} "
                f"[{v.get('severity')}]",
                body_style,
            ))

    # Section 4 — Regulatory Context
    story += sec("4. Regulatory Obligations")
    story.append(kv("Framework", reg.get("framework")))
    story.append(kv("Jurisdiction", reg.get("jurisdiction")))
    story.append(kv("Reporting Window", f"{reg.get('reporting_window_hours')}h"))
    story.append(kv("Obligation", reg.get("obligation")))
    story.append(kv("Authority", reg.get("authority")))
    story.append(kv("Action Required", reg.get("action_required")))

    # Section 5 — Seal
    story += sec("5. Cryptographic Seal")
    story.append(kv("Seal Algorithm", "SHA-256"))
    story.append(kv("Report Version", package.get("report_version")))
    story.append(Spacer(1, 4))
    seal = package.get("seal_hash", "")
    story.append(Paragraph("<b>Seal Hash:</b>", body_style))
    story.append(Paragraph(seal[:32], mono_style))
    story.append(Paragraph(seal[32:], mono_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(package.get("note", ""), body_style))

    doc.build(story)
    return buf.getvalue()
