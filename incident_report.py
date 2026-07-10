"""
incident_report.py — Pulse AI Governance Middleware
Same interface as before: assemble_evidence_package() + render_incident_pdf()
RFC 3161 timestamp section added to PDF output.
"""

import hashlib
import json
import base64
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# assemble_evidence_package — same signature as before
# ---------------------------------------------------------------------------

def assemble_evidence_package(
    *,
    hold: Dict[str, Any],
    agent_events: Optional[List[Dict[str, Any]]] = None,
    exfiltration: Optional[Dict[str, Any]] = None,
    policy_violations: Optional[List[Any]] = None,
    swarm: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build the structured JSON evidence package.
    Includes RFC 3161 tsa_token_b64 if present on the hold.
    """
    now = datetime.now(timezone.utc).isoformat()
    tsa_token_b64 = hold.get("tsa_token_b64")

    package = {
        "hold_id":          hold.get("id"),
        "agent_id":         hold.get("agent_id"),
        "session_id":       hold.get("session_id"),
        "trigger_type":     hold.get("trigger_type"),
        "severity":         hold.get("severity"),
        "status":           hold.get("status"),
        "created_at":       hold.get("created_at"),
        "reason":           hold.get("reason"),
        "framework":        hold.get("framework"),
        "jurisdiction":     hold.get("jurisdiction"),
        "chain_hash":       hold.get("chain_hash"),
        "seal_hash":        hold.get("seal_hash"),
        # RFC 3161
        "tsa_status":       hold.get("tsa_status", "INTERNAL_SEAL_ONLY"),
        "tsa_token_b64":    tsa_token_b64,
        "tsa_stamped_at":   hold.get("tsa_stamped_at"),
        "tsa_endpoint":     hold.get("tsa_endpoint"),
        # Signals
        "exfiltration":     exfiltration or {},
        "policy_violations": policy_violations or [],
        "swarm":            swarm or {},
        "evidence":         hold.get("evidence") or {},
        # Event annex
        "event_count":      len(agent_events or []),
        "recent_events":    (agent_events or [])[:20],
        # Meta
        "generated_at":     now,
        "package_version":  "2.0",
        "generated_by":     "Pulse AI Governance Middleware",
    }

    # Compute package fingerprint
    fingerprint_dict = {
        "hold_id":      package["hold_id"],
        "seal_hash":    package["seal_hash"],
        "chain_hash":   package["chain_hash"],
        "tsa_stamped":  bool(tsa_token_b64),
        "generated_at": now,
    }
    package["package_fingerprint"] = hashlib.sha256(
        json.dumps(fingerprint_dict, sort_keys=True).encode()
    ).hexdigest()

    return package


# ---------------------------------------------------------------------------
# render_incident_pdf — same signature as before
# ---------------------------------------------------------------------------

def render_incident_pdf(evidence_package: Dict[str, Any]) -> bytes:
    """
    Generate a sealed incident evidence package PDF.
    Raises RuntimeError if reportlab is not installed.
    Returns raw PDF bytes.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        raise RuntimeError(
            "reportlab is not installed. Add 'reportlab' to requirements.txt."
        )

    import io
    buf = io.BytesIO()

    # Colours
    PULSE_DARK  = colors.HexColor("#0f172a")
    PULSE_BLUE  = colors.HexColor("#3b82f6")
    PULSE_GREEN = colors.HexColor("#10b981")
    PULSE_RED   = colors.HexColor("#ef4444")
    PULSE_AMBER = colors.HexColor("#f59e0b")
    PULSE_GREY  = colors.HexColor("#64748b")
    PULSE_LIGHT = colors.HexColor("#f8fafc")
    TSA_GOLD    = colors.HexColor("#d97706")

    base = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    s_title    = S("title",   fontSize=18, leading=22, textColor=PULSE_DARK, spaceAfter=4, fontName="Helvetica-Bold")
    s_sub      = S("sub",     fontSize=10, textColor=PULSE_GREY, spaceAfter=12)
    s_section  = S("section", fontSize=11, leading=14, textColor=PULSE_BLUE, spaceBefore=10, spaceAfter=4, fontName="Helvetica-Bold")
    s_tsa_sec  = S("tsasec",  fontSize=11, leading=14, textColor=TSA_GOLD,   spaceBefore=10, spaceAfter=4, fontName="Helvetica-Bold")
    s_body     = S("body",    fontSize=9,  leading=13, textColor=PULSE_DARK)
    s_mono     = S("mono",    fontSize=7.5, leading=11, textColor=PULSE_DARK, fontName="Courier")
    s_mono_sm  = S("monosm", fontSize=6.5, leading=10, textColor=PULSE_GREY, fontName="Courier")
    s_label    = S("label",   fontSize=8,  textColor=PULSE_GREY, spaceAfter=1)
    s_value    = S("value",   fontSize=9,  textColor=PULSE_DARK)
    s_tsa_ok   = S("tsaok",  fontSize=10, textColor=PULSE_GREEN, leading=14, fontName="Helvetica-Bold")
    s_tsa_warn = S("tsawarn", fontSize=10, textColor=PULSE_AMBER, leading=14, fontName="Helvetica-Bold")

    def kv_table(rows, w1=55, w2=115):
        data = [
            [Paragraph(f"<b>{k}</b>", s_label), Paragraph(str(v), s_value)]
            for k, v in rows
        ]
        t = Table(data, colWidths=[w1*mm, w2*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), PULSE_LIGHT),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ]))
        return t

    def rule(color=PULSE_BLUE):
        return HRFlowable(width="100%", thickness=0.5, color=color, spaceAfter=4)

    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm, bottomMargin=18*mm)

    E = []  # elements list
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    hold_id      = evidence_package.get("hold_id", "UNKNOWN")
    agent_id     = evidence_package.get("agent_id", "—")
    session_id   = evidence_package.get("session_id", "—")
    trigger_type = evidence_package.get("trigger_type", "—")
    severity     = (evidence_package.get("severity") or "—").upper()
    seal_hash    = evidence_package.get("seal_hash", "—")
    chain_hash   = evidence_package.get("chain_hash", "—")
    tsa_token_b64 = evidence_package.get("tsa_token_b64")
    tsa_status   = evidence_package.get("tsa_status", "INTERNAL_SEAL_ONLY")
    tsa_label    = "RFC 3161 TIMESTAMPED" if tsa_token_b64 else "INTERNAL SEAL"

    # ── Page 1: Header + Summary ──────────────────────────────────────────
    E.append(Paragraph("PULSE", s_title))
    E.append(Paragraph("AI Agent Governance Middleware · Sealed Incident Evidence Package", s_sub))

    banner = Table([[
        Paragraph("<b>CONFIDENTIAL — REGULATORY EVIDENCE</b>",
                  ParagraphStyle("b1", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph(f"<b>{tsa_label}</b>",
                  ParagraphStyle("b2", fontSize=9,
                                 textColor=colors.white if tsa_token_b64 else PULSE_DARK,
                                 alignment=TA_CENTER)),
    ]], colWidths=[115*mm, 55*mm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), PULSE_DARK),
        ("BACKGROUND", (1,0), (1,0), TSA_GOLD if tsa_token_b64 else PULSE_AMBER),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    E.append(banner)
    E.append(Spacer(1, 10))

    E.append(Paragraph("§1 — Incident Summary", s_section))
    E.append(rule())
    E.append(kv_table([
        ("Hold ID",          hold_id),
        ("Agent ID",         agent_id),
        ("Session ID",       session_id),
        ("Trigger Type",     trigger_type),
        ("Severity",         severity),
        ("Status",           evidence_package.get("status", "—")),
        ("Created At",       evidence_package.get("created_at", "—")),
        ("Framework",        evidence_package.get("framework", "—")),
        ("Jurisdiction",     evidence_package.get("jurisdiction", "—")),
        ("Report Generated", now_str),
    ]))

    # ── Page 2: Evidence signals ──────────────────────────────────────────
    E.append(PageBreak())
    E.append(Paragraph("§2 — Detection Signals", s_section))
    E.append(rule())
    exfil = evidence_package.get("exfiltration") or {}
    swarm = evidence_package.get("swarm") or {}
    pviol = evidence_package.get("policy_violations") or []
    E.append(kv_table([
        ("Exfiltration Risk Score", str(exfil.get("risk_score", "—"))),
        ("Exfiltration Alert",      str(exfil.get("alert", False))),
        ("Swarm Suspect",           str(swarm.get("swarm_suspect", False))),
        ("Active Sessions",         str(swarm.get("active_sessions", "—"))),
        ("Policy Violations",       str(len(pviol)) if pviol else "0"),
        ("Chain Hash",              chain_hash),
        ("Seal Hash",               seal_hash),
    ]))
    E.append(Spacer(1, 10))

    E.append(Paragraph("§3 — ASEAN Regulatory Mapping", s_section))
    E.append(rule())
    reg_data = [
        ["Jurisdiction", "Regulation", "Deadline", "Status"],
        ["Malaysia",  "PDPA 2010 (Amended 2024)",               "72hr (rec. 24hr)", "NOTIFY REQUIRED"],
        ["Singapore", "PDPA + Model AI Governance Framework",    "72hr",             "NOTIFY REQUIRED"],
        ["Vietnam",   "AI Law 2024 (Art. 9)",                   "72hr",             "NOTIFY REQUIRED"],
        ["Regional",  "ISO/IEC 42001",                           "168hr (7 days)",   "DOCUMENT & RETAIN"],
    ]
    rt = Table(reg_data, colWidths=[28*mm, 70*mm, 32*mm, 40*mm])
    rt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), PULSE_DARK),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [PULSE_LIGHT, colors.white]),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
        ("BACKGROUND", (-1,1), (-1,-1), colors.HexColor("#fef2f2")),
        ("TEXTCOLOR",  (-1,1), (-1,-1), PULSE_RED),
        ("FONTNAME",   (-1,1), (-1,-1), "Helvetica-Bold"),
    ]))
    E.append(rt)

    # ── Page 3: RFC 3161 Trusted Timestamp ───────────────────────────────
    E.append(PageBreak())
    E.append(Paragraph("§4 — RFC 3161 Trusted Timestamp Certificate", s_tsa_sec))
    E.append(rule(TSA_GOLD))
    E.append(Spacer(1, 4))

    if tsa_token_b64:
        E.append(Paragraph("✓  EXTERNALLY TIMESTAMPED — RFC 3161 Compliant", s_tsa_ok))
        E.append(Spacer(1, 6))
        E.append(Paragraph(
            "This evidence package was presented to an independent Timestamp Authority (TSA) "
            "at the moment of sealing. The TSA cryptographically signed the seal hash, producing "
            "a timestamp token verifiable by any RFC 3161-compliant tool without trusting Pulse.",
            s_body,
        ))
        E.append(Spacer(1, 8))
        tsa_time = evidence_package.get("tsa_stamped_at", "—")
        try:
            import rfc3161ng
            tsr_bytes = base64.b64decode(tsa_token_b64)
            ts = rfc3161ng.get_timestamp(rfc3161ng.decode_timestamp_response(tsr_bytes))
            if ts:
                tsa_time = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            pass
        E.append(kv_table([
            ("TSA Certified Time", tsa_time),
            ("TSA Endpoint",       evidence_package.get("tsa_endpoint") or "RFC 3161 compliant TSA"),
            ("Algorithm",          "SHA-256"),
            ("Seal Hash Stamped",  seal_hash),
            ("Token Format",       "RFC 3161 Timestamp Response (TSR, DER-encoded)"),
            ("Verify Command",     "openssl ts -verify -in token.tsr -digest <seal_hash> -CAfile tsa_ca.pem"),
        ]))
        E.append(Spacer(1, 8))
        E.append(Paragraph("<b>Timestamp Token (Base64 TSR — first 300 chars)</b>", s_label))
        E.append(Spacer(1, 3))
        preview = tsa_token_b64[:300] + ("..." if len(tsa_token_b64) > 300 else "")
        E.append(Paragraph(preview, s_mono_sm))
        E.append(Spacer(1, 6))
        E.append(Paragraph(
            "The full token is in the JSON evidence package (field: tsa_token_b64). "
            "Decode with base64 → token.tsr, then run the verify command above.",
            s_body,
        ))
    else:
        E.append(Paragraph("⚠  INTERNAL SEAL ONLY — External TSA Unavailable at Seal Time", s_tsa_warn))
        E.append(Spacer(1, 6))
        E.append(Paragraph(
            "No external Timestamp Authority was reachable when this hold was sealed. "
            "The SHA-256 seal hash below proves internal tamper-evidence but does not carry "
            "a third-party certified timestamp.",
            s_body,
        ))
        E.append(Spacer(1, 8))
        E.append(kv_table([
            ("Seal Hash",      seal_hash),
            ("TSA Status",     "Unavailable at seal time"),
            ("Recovery",       "Re-stamp seal_hash via openssl ts -query against any public TSA."),
        ]))

    # ── Page 4: Chain of custody + attestation ───────────────────────────
    E.append(PageBreak())
    E.append(Paragraph("§5 — Chain of Custody & Attestation", s_section))
    E.append(rule())
    E.append(kv_table([
        ("Audit Chain Hash",    chain_hash),
        ("Evidence Seal Hash",  seal_hash),
        ("Seal Algorithm",      "SHA-256 (evidence JSON + chain_hash + hold_id)"),
        ("External Timestamp",  "RFC 3161 TSR" if tsa_token_b64 else "Not available at seal time"),
        ("Storage Region",      "Supabase ap-southeast-1 (Singapore)"),
        ("Hash Chain Tables",   "ai_events + audit_logs (dual SHA-256 chain)"),
        ("Package Fingerprint", evidence_package.get("package_fingerprint", "—")),
    ]))
    E.append(Spacer(1, 10))

    attest = Table([[Paragraph(
        f"This document is a sealed forensic evidence package generated by Pulse AI Governance "
        f"Middleware. Evidence was captured in real-time and sealed with a SHA-256 hash chain at "
        f"{evidence_package.get('created_at', now_str)}. "
        + ("An RFC 3161 timestamp token from an independent TSA provides cryptographic proof of "
           "the seal time, verifiable without Pulse. "
           if tsa_token_b64 else
           "Note: External TSA timestamping was unavailable at seal time. ")
        + f"This package is suitable for submission to regulatory bodies under PDPA Malaysia, "
          f"Singapore PDPA, and Vietnam AI Law. Hold ID: {hold_id}.",
        s_body,
    )]], colWidths=[170*mm])
    attest.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), PULSE_LIGHT),
        ("BOX",        (0,0), (-1,-1), 0.8, PULSE_DARK),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
    ]))
    E.append(attest)

    doc.build(E)
    return buf.getvalue()
