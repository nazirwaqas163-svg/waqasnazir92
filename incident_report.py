"""
incident_report.py — Pulse AI Governance Middleware
Sealed incident evidence package PDF, including RFC 3161 trusted timestamp section.

PDF structure:
  Page 1 — Header, classification, incident summary
  Page 2 — Evidence inventory, BDI/entropy/threat signals
  Page 3 — ASEAN regulatory mapping (PDPA MY / SGP MGF / VN AI Law)
  Page 4 — RFC 3161 Trusted Timestamp Certificate  ← NEW
  Page 5 — Chain of custody, seal hash, attestation
"""

import hashlib
import json
import base64
import logging
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
PULSE_DARK   = colors.HexColor("#0f172a")
PULSE_BLUE   = colors.HexColor("#3b82f6")
PULSE_GREEN  = colors.HexColor("#10b981")
PULSE_RED    = colors.HexColor("#ef4444")
PULSE_AMBER  = colors.HexColor("#f59e0b")
PULSE_GREY   = colors.HexColor("#64748b")
PULSE_LIGHT  = colors.HexColor("#f8fafc")
TSA_GOLD     = colors.HexColor("#d97706")   # amber-600 — trusted timestamp accent


# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------

def _styles():
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "title", parent=base["Title"],
            fontSize=18, leading=22, textColor=PULSE_DARK, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"],
            fontSize=10, textColor=PULSE_GREY, spaceAfter=12,
        ),
        "section": ParagraphStyle(
            "section", parent=base["Heading2"],
            fontSize=11, leading=14, textColor=PULSE_BLUE,
            spaceBefore=10, spaceAfter=4, borderPad=2,
        ),
        "tsa_section": ParagraphStyle(
            "tsa_section", parent=base["Heading2"],
            fontSize=11, leading=14, textColor=TSA_GOLD,
            spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"],
            fontSize=9, leading=13, textColor=PULSE_DARK,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Normal"],
            fontSize=7.5, leading=11, textColor=PULSE_DARK,
            fontName="Courier",
        ),
        "mono_small": ParagraphStyle(
            "mono_small", parent=base["Normal"],
            fontSize=6.5, leading=10, textColor=PULSE_GREY,
            fontName="Courier",
        ),
        "label": ParagraphStyle(
            "label", parent=base["Normal"],
            fontSize=8, textColor=PULSE_GREY, spaceAfter=1,
        ),
        "value": ParagraphStyle(
            "value", parent=base["Normal"],
            fontSize=9, textColor=PULSE_DARK, spaceBefore=0,
        ),
        "badge_red": ParagraphStyle(
            "badge_red", parent=base["Normal"],
            fontSize=9, textColor=colors.white,
            backColor=PULSE_RED, borderRadius=3,
            alignment=TA_CENTER,
        ),
        "badge_green": ParagraphStyle(
            "badge_green", parent=base["Normal"],
            fontSize=9, textColor=colors.white,
            backColor=PULSE_GREEN, borderRadius=3,
            alignment=TA_CENTER,
        ),
        "tsa_verified": ParagraphStyle(
            "tsa_verified", parent=base["Normal"],
            fontSize=10, textColor=PULSE_GREEN, leading=14,
        ),
        "tsa_warn": ParagraphStyle(
            "tsa_warn", parent=base["Normal"],
            fontSize=10, textColor=PULSE_AMBER, leading=14,
        ),
        "footer": ParagraphStyle(
            "footer", parent=base["Normal"],
            fontSize=7, textColor=PULSE_GREY, alignment=TA_CENTER,
        ),
    }
    return styles


def _kv_table(rows: list, col_widths=None) -> Table:
    """Two-column label/value table."""
    col_widths = col_widths or [55 * mm, 115 * mm]
    s = _styles()
    data = [
        [Paragraph(f"<b>{k}</b>", s["label"]), Paragraph(str(v), s["value"])]
        for k, v in rows
    ]
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PULSE_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _section_rule():
    return HRFlowable(width="100%", thickness=0.5, color=PULSE_BLUE, spaceAfter=4)


def _tsa_rule():
    return HRFlowable(width="100%", thickness=0.5, color=TSA_GOLD, spaceAfter=4)


# ---------------------------------------------------------------------------
# RFC 3161 section builder
# ---------------------------------------------------------------------------

def _build_tsa_section(hold: dict, s: dict) -> list:
    """
    Build the RFC 3161 Trusted Timestamp Certificate page content.
    """
    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph("§4 — RFC 3161 Trusted Timestamp Certificate", s["tsa_section"]))
    elements.append(_tsa_rule())
    elements.append(Spacer(1, 4))

    tsa_token_b64 = hold.get("tsa_token_b64")
    tsa_stamped_at = hold.get("tsa_stamped_at")
    tsa_endpoint = hold.get("tsa_endpoint")
    seal_hash = hold.get("seal_hash", "")

    if tsa_token_b64:
        # --- Verified block ---
        elements.append(Paragraph(
            "✓  EXTERNALLY TIMESTAMPED — RFC 3161 Compliant",
            s["tsa_verified"],
        ))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(
            "This evidence package was presented to an independent Timestamp Authority (TSA) at the "
            "moment of sealing. The TSA cryptographically signed the seal hash, producing a timestamp "
            "token that can be verified by any RFC 3161-compliant tool without trusting Pulse.",
            s["body"],
        ))
        elements.append(Spacer(1, 8))

        # Decode to get timestamp
        tsa_time_str = tsa_stamped_at or "—"
        try:
            import rfc3161ng
            tsr_bytes = base64.b64decode(tsa_token_b64)
            ts = rfc3161ng.get_timestamp(rfc3161ng.decode_timestamp_response(tsr_bytes))
            if ts:
                tsa_time_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            pass

        elements.append(_kv_table([
            ("TSA Certified Time",   tsa_time_str),
            ("TSA Endpoint",         tsa_endpoint or "RFC 3161 compliant TSA"),
            ("Algorithm",            "SHA-256"),
            ("Seal Hash Stamped",    seal_hash),
            ("Token Format",         "RFC 3161 Timestamp Response (TSR, DER-encoded)"),
            ("Verification",         "openssl ts -verify -in token.tsr -digest <seal_hash> -CAfile tsa_ca.pem"),
        ]))
        elements.append(Spacer(1, 10))

        # Token preview (truncated)
        elements.append(Paragraph("<b>Timestamp Token (Base64, RFC 3161 TSR)</b>", s["label"]))
        elements.append(Spacer(1, 3))
        token_preview = tsa_token_b64[:300] + "..." if len(tsa_token_b64) > 300 else tsa_token_b64
        elements.append(Paragraph(token_preview, s["mono_small"]))
        elements.append(Spacer(1, 6))

        # Full token note
        elements.append(Paragraph(
            "The complete TSR token is included in the JSON evidence package "
            "(field: tsa_token_b64). To verify independently:",
            s["body"],
        ))
        elements.append(Spacer(1, 4))
        verify_steps = [
            "1.  Extract tsa_token_b64 from the JSON package and base64-decode to token.tsr",
            "2.  Run: openssl ts -verify -in token.tsr -digest $(echo -n '<seal_hash>' | sha256sum) -CAfile tsa_ca.pem",
            "3.  Confirmed timestamp = evidence existed in this exact state at TSA-certified time",
        ]
        for step in verify_steps:
            elements.append(Paragraph(step, s["mono"]))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            "This timestamp is binding regardless of Pulse system availability. "
            "It constitutes evidence of existence under PDPA Malaysia Section 30, "
            "Singapore PDPC breach notification requirements, and Vietnam AI Law Article 9.",
            s["body"],
        ))

    else:
        # --- No token block ---
        elements.append(Paragraph(
            "⚠  INTERNAL SEAL ONLY — External TSA Unavailable at Seal Time",
            s["tsa_warn"],
        ))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(
            "This hold was sealed with an internal SHA-256 chain hash. No external Timestamp "
            "Authority was reachable at the moment of sealing. The seal hash below proves "
            "internal tamper-evidence but does not carry a third-party certified timestamp.",
            s["body"],
        ))
        elements.append(Spacer(1, 8))
        elements.append(_kv_table([
            ("Seal Hash",     seal_hash),
            ("Sealed At",     hold.get("sealed_at", "—")),
            ("TSA Status",    "Unavailable — internal seal only"),
            ("Recommendation",
             "Re-stamp seal_hash via 'openssl ts -query' against a TSA when connectivity "
             "is restored to obtain a retrospective RFC 3161 token."),
        ]))

    return elements


# ---------------------------------------------------------------------------
# Main PDF builder
# ---------------------------------------------------------------------------

def generate_incident_report_pdf(hold: dict, events: Optional[list] = None) -> bytes:
    """
    Generate a sealed incident evidence package PDF.
    Returns raw PDF bytes.

    Args:
        hold:   Legal hold row dict from Supabase (legal_holds table).
                Must include: id, trigger_type, agent_id, session_id,
                severity, evidence (JSONB), seal_hash, chain_hash,
                tsa_token_b64, tsa_stamped_at, tsa_endpoint, created_at.
        events: Optional list of related ai_events rows for evidence annex.
    """
    import io
    buf = io.BytesIO()
    s = _styles()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    elements = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    hold_id = hold.get("id", "UNKNOWN")
    agent_id = hold.get("agent_id", "—")
    session_id = hold.get("session_id", "—")
    trigger_type = hold.get("trigger_type", "—")
    severity = hold.get("severity", "—").upper()
    seal_hash = hold.get("seal_hash", "—")
    chain_hash = hold.get("chain_hash", "—")
    evidence = hold.get("evidence", {})
    tsa_token_b64 = hold.get("tsa_token_b64")

    severity_color = {
        "CRITICAL": PULSE_RED,
        "HIGH": PULSE_RED,
        "MEDIUM": PULSE_AMBER,
        "LOW": PULSE_GREEN,
    }.get(severity, PULSE_GREY)

    # -----------------------------------------------------------------------
    # PAGE 1 — Header + Incident Summary
    # -----------------------------------------------------------------------
    elements.append(Paragraph("PULSE", s["title"]))
    elements.append(Paragraph(
        "AI Agent Governance Middleware · Sealed Incident Evidence Package",
        s["subtitle"],
    ))

    # Classification banner
    tsa_label = "RFC 3161 TIMESTAMPED" if tsa_token_b64 else "INTERNAL SEAL"
    banner_data = [[
        Paragraph("<b>CONFIDENTIAL — REGULATORY EVIDENCE</b>", ParagraphStyle(
            "banner", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph(f"<b>{tsa_label}</b>", ParagraphStyle(
            "tsa_banner", fontSize=9,
            textColor=colors.white if tsa_token_b64 else PULSE_DARK,
            alignment=TA_CENTER)),
    ]]
    banner_table = Table(banner_data, colWidths=[115 * mm, 55 * mm])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), PULSE_DARK),
        ("BACKGROUND", (1, 0), (1, 0), TSA_GOLD if tsa_token_b64 else PULSE_AMBER),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(banner_table)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("§1 — Incident Summary", s["section"]))
    elements.append(_section_rule())
    elements.append(_kv_table([
        ("Hold ID",          hold_id),
        ("Agent ID",         agent_id),
        ("Session ID",       session_id),
        ("Trigger Type",     trigger_type),
        ("Severity",         severity),
        ("Hold Status",      hold.get("status", "—").upper()),
        ("Created At",       hold.get("created_at", "—")),
        ("Sealed At",        hold.get("sealed_at", now_str)),
        ("Reporting System", "Pulse AI Governance Middleware v1.0"),
        ("Report Generated", now_str),
    ]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("§2 — Evidence Inventory", s["section"]))
    elements.append(_section_rule())

    evidence_rows = []
    for k, v in evidence.items():
        val_str = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        evidence_rows.append((k, val_str[:200] + ("…" if len(val_str) > 200 else "")))

    if evidence_rows:
        elements.append(_kv_table(evidence_rows))
    else:
        elements.append(Paragraph("No structured evidence fields recorded.", s["body"]))

    elements.append(Spacer(1, 10))

    # Threat signals
    bdi = evidence.get("bdi_score", evidence.get("bdi", "—"))
    entropy = evidence.get("entropy", "—")
    threat_class = evidence.get("threat_classification", evidence.get("threat_class", "—"))
    exfil_risk = evidence.get("exfiltration_risk", "—")

    elements.append(Paragraph("Detection Signals", s["section"]))
    elements.append(_section_rule())
    elements.append(_kv_table([
        ("BDI Score",              str(bdi)),
        ("Shannon Entropy",        str(entropy)),
        ("Threat Classification",  str(threat_class)),
        ("Exfiltration Risk",      str(exfil_risk)),
        ("Policy Violations",      str(evidence.get("policy_violations", "none"))),
        ("Swarm Detected",         str(evidence.get("swarm_detected", False))),
    ]))

    # -----------------------------------------------------------------------
    # PAGE 2 — ASEAN Regulatory Mapping
    # -----------------------------------------------------------------------
    elements.append(PageBreak())
    elements.append(Paragraph("§3 — ASEAN Regulatory Mapping", s["section"]))
    elements.append(_section_rule())
    elements.append(Spacer(1, 4))

    reg_data = [
        ["Jurisdiction", "Regulation", "Obligation", "Deadline", "Status"],
        [
            "Malaysia",
            "PDPA 2010\n(Amended 2024)",
            "Data breach notification\nto PDPC + affected subjects",
            "72 hours\n(Recommended 24hr)",
            "NOTIFY REQUIRED",
        ],
        [
            "Singapore",
            "PDPA + Model AI\nGovernance Framework",
            "Mandatory breach notification\nif >500 individuals affected",
            "3 calendar days\n(72 hours)",
            "NOTIFY REQUIRED",
        ],
        [
            "Vietnam",
            "AI Law 2024\n(Art. 9)",
            "AI incident reporting\nto competent authority",
            "72 hours",
            "NOTIFY REQUIRED",
        ],
        [
            "Regional",
            "ISO/IEC 42001",
            "AI management system\nincident documentation",
            "168 hours (7 days)",
            "DOCUMENT & RETAIN",
        ],
    ]

    reg_table = Table(reg_data, colWidths=[25*mm, 32*mm, 55*mm, 28*mm, 30*mm])
    reg_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PULSE_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PULSE_LIGHT, colors.white]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (-1, 1), (-1, -1), colors.HexColor("#fef2f2")),
        ("TEXTCOLOR", (-1, 1), (-1, -1), PULSE_RED),
        ("FONTNAME", (-1, 1), (-1, -1), "Helvetica-Bold"),
    ]))
    elements.append(reg_table)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(
        "Action Required: DPO or designated compliance officer must assess notification "
        "obligations under each applicable jurisdiction and initiate regulatory contact "
        "within the stated deadline windows from incident detection time.",
        s["body"],
    ))

    # -----------------------------------------------------------------------
    # PAGE 3 — RFC 3161 Trusted Timestamp Certificate
    # -----------------------------------------------------------------------
    elements += _build_tsa_section(hold, s)

    # -----------------------------------------------------------------------
    # PAGE 4 — Chain of Custody + Seal + Attestation
    # -----------------------------------------------------------------------
    elements.append(PageBreak())
    elements.append(Paragraph("§5 — Chain of Custody & Attestation", s["section"]))
    elements.append(_section_rule())
    elements.append(Spacer(1, 4))

    elements.append(_kv_table([
        ("Audit Ledger Chain Hash",    chain_hash),
        ("Evidence Seal Hash",         seal_hash),
        ("Seal Algorithm",             "SHA-256 (evidence JSON + chain_hash + hold_id)"),
        ("Audit Table",                "ai_events + audit_logs (Supabase Singapore ap-southeast-1)"),
        ("Hash Chain Type",            "SHA-256 linked chain (prev_hash → row_hash)"),
        ("External Timestamp",         "RFC 3161 TSR" if tsa_token_b64 else "Not available at seal time"),
        ("Ledger Integrity Endpoint",  "GET /ledger/integrity"),
        ("Storage Region",             "Supabase ap-southeast-1 (Singapore)"),
    ]))
    elements.append(Spacer(1, 10))

    # Evidence package fingerprint
    package_dict = {
        "hold_id": hold_id,
        "seal_hash": seal_hash,
        "chain_hash": chain_hash,
        "tsa_stamped": bool(tsa_token_b64),
        "generated_at": now_str,
    }
    pkg_hash = hashlib.sha256(json.dumps(package_dict, sort_keys=True).encode()).hexdigest()

    elements.append(Paragraph("<b>Evidence Package Fingerprint</b>", s["label"]))
    elements.append(Spacer(1, 2))
    elements.append(Paragraph(pkg_hash, s["mono"]))
    elements.append(Spacer(1, 12))

    # Attestation box
    attest_data = [[Paragraph(
        f"This document is a sealed forensic evidence package generated by Pulse AI Governance "
        f"Middleware. The evidence contained herein was captured in real-time during agent operation "
        f"and sealed with a SHA-256 hash chain at {hold.get('sealed_at', now_str)}. "
        f"{'An RFC 3161 timestamp token from an independent Timestamp Authority provides cryptographic proof of the seal time, verifiable without Pulse.' if tsa_token_b64 else 'Note: External TSA timestamping was unavailable at seal time.'} "
        f"This package is suitable for submission to regulatory bodies under PDPA Malaysia, "
        f"Singapore PDPA, and Vietnam AI Law. Hold ID: {hold_id}.",
        s["body"],
    )]]
    attest_table = Table(attest_data, colWidths=[170 * mm])
    attest_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PULSE_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.8, PULSE_DARK),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(attest_table)
    elements.append(Spacer(1, 8))

    # Optional event annex
    if events:
        elements.append(PageBreak())
        elements.append(Paragraph("Annex A — Related Event Records", s["section"]))
        elements.append(_section_rule())
        annex_data = [["Event ID", "Timestamp", "BDI", "Entropy", "Threat Class"]]
        for ev in events[:30]:
            annex_data.append([
                str(ev.get("event_id", "—"))[:20],
                str(ev.get("created_at", "—"))[:19],
                str(ev.get("bdi_score", "—")),
                str(ev.get("entropy", "—")),
                str(ev.get("threat_classification", "—")),
            ])
        annex_table = Table(annex_data, colWidths=[35*mm, 40*mm, 20*mm, 20*mm, 55*mm])
        annex_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PULSE_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PULSE_LIGHT, colors.white]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(annex_table)

    doc.build(elements)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# JSON evidence package (for GET /legal-hold/{id}/evidence-package)
# ---------------------------------------------------------------------------

def build_evidence_package_json(hold: dict, events: Optional[list] = None) -> dict:
    """
    Build the structured JSON evidence package.
    Includes tsa_token_b64 for independent verification.
    """
    tsa_token_b64 = hold.get("tsa_token_b64")
    return {
        "hold_id":          hold.get("id"),
        "agent_id":         hold.get("agent_id"),
        "session_id":       hold.get("session_id"),
        "trigger_type":     hold.get("trigger_type"),
        "severity":         hold.get("severity"),
        "status":           hold.get("status"),
        "created_at":       hold.get("created_at"),
        "sealed_at":        hold.get("sealed_at"),
        "seal_hash":        hold.get("seal_hash"),
        "chain_hash":       hold.get("chain_hash"),
        "evidence":         hold.get("evidence", {}),
        "org_id":           hold.get("org_id"),
        # RFC 3161 fields
        "tsa_status":       "RFC_3161_STAMPED" if tsa_token_b64 else "INTERNAL_SEAL_ONLY",
        "tsa_token_b64":    tsa_token_b64,
        "tsa_stamped_at":   hold.get("tsa_stamped_at"),
        "tsa_endpoint":     hold.get("tsa_endpoint"),
        # Annex
        "related_events":   events or [],
        "package_version":  "2.0",
        "generated_by":     "Pulse AI Governance Middleware",
    }
