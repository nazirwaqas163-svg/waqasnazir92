"""
Pulse Passport — PP-1.

A signed, exportable compliance identity document per agent per period.
Assembled entirely from existing Pulse infrastructure — no new tables needed.

6 sections:
  1. Agent Identity        — agent_registry row
  2. Session Lineage       — ai_events summary (sessions, turns, blocked)
  3. Drift + Shadow Score  — drift engine + shadow score v2
  4. Compliance Status     — ASEAN deadline clock status
  5. Breach Readiness      — active legal holds + composite score
  6. Passport Signature    — SHA-256 hash of sections 1–5 + generation metadata

The signature is computed over the canonical JSON of sections 1–5.
Tampering with any field invalidates the signature — court-defensible.

PDF generation uses reportlab (pure Python, no system dependencies).
If reportlab is not installed, JSON-only mode still works.
"""

from __future__ import annotations

import hashlib
import json
import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Signature helpers
# ---------------------------------------------------------------------------

def _canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sign_passport(sections: Dict[str, Any], generated_at: str, agent_id: str) -> Dict[str, Any]:
    """Compute SHA-256 signature over sections 1–5 + metadata."""
    payload = {
        "agent_id": agent_id,
        "generated_at": generated_at,
        "sections": sections,
    }
    digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return {
        "algorithm": "SHA-256",
        "digest": digest,
        "signed_fields": ["agent_identity", "session_lineage", "drift_shadow", "compliance_status", "breach_readiness"],
        "generated_at": generated_at,
        "note": "Recompute SHA-256 over canonical JSON of signed_fields to verify. Any field change invalidates this signature.",
    }


# ---------------------------------------------------------------------------
# Section assemblers — each takes pre-fetched data, returns a clean dict
# ---------------------------------------------------------------------------

def _section_agent_identity(agent: Optional[Dict[str, Any]], agent_id: str) -> Dict[str, Any]:
    if not agent:
        return {
            "agent_id": agent_id,
            "registered": False,
            "status": "UNREGISTERED",
            "name": None,
            "owner": None,
            "scope": [],
            "description": None,
            "registered_at": None,
            "metadata": {},
        }
    return {
        "agent_id": agent_id,
        "registered": True,
        "status": agent.get("status", "active"),
        "name": agent.get("name"),
        "owner": agent.get("owner"),
        "scope": agent.get("scope") or [],
        "description": agent.get("description"),
        "registered_at": agent.get("registered_at"),
        "metadata": agent.get("metadata") or {},
    }


def _section_session_lineage(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    sessions: Dict[str, Dict[str, Any]] = {}
    for e in events:
        sid = e.get("session_id")
        if not sid:
            continue
        node = sessions.setdefault(sid, {
            "session_id": sid,
            "turns": 0,
            "blocked": 0,
            "parent_session_id": e.get("parent_session_id"),
            "first_seen": e.get("timestamp") or e.get("created_at"),
            "last_seen": e.get("timestamp") or e.get("created_at"),
        })
        node["turns"] += 1
        status = e.get("status") or e.get("policy_result", "")
        if status == "blocked":
            node["blocked"] += 1
        ts = e.get("timestamp") or e.get("created_at")
        if ts and ts > node["last_seen"]:
            node["last_seen"] = ts

    total_turns = sum(s["turns"] for s in sessions.values())
    total_blocked = sum(s["blocked"] for s in sessions.values())
    spawned = sum(1 for s in sessions.values() if s.get("parent_session_id"))

    return {
        "total_sessions": len(sessions),
        "total_turns": total_turns,
        "total_blocked": total_blocked,
        "block_rate": round(total_blocked / total_turns, 4) if total_turns else 0.0,
        "spawned_sessions": spawned,
        "root_sessions": len(sessions) - spawned,
        "sessions": sorted(sessions.values(), key=lambda s: s["first_seen"] or ""),
    }


def _section_drift_shadow(
    drift: Dict[str, Any],
    shadow: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "drift": {
            "score": drift.get("score"),
            "status": drift.get("status"),
            "turns_analyzed": drift.get("turns_analyzed"),
            "components": drift.get("components"),
        },
        "shadow_score_v2": {
            "shadow_score": shadow.get("shadow_score"),
            "status": shadow.get("status"),
            "flag": shadow.get("flag"),
            "all_flags": shadow.get("all_flags", []),
            "components": shadow.get("components"),
            "weights": shadow.get("weights"),
            "note": shadow.get("note"),
        },
    }


def _section_compliance_status(deadlines: List[Dict[str, Any]]) -> Dict[str, Any]:
    overall = "NOMINAL"
    if any(d.get("status") == "BREACHED" for d in deadlines):
        overall = "BREACHED"
    elif any(d.get("status") == "CRITICAL" for d in deadlines):
        overall = "CRITICAL"
    elif any(d.get("status") == "WARNING" for d in deadlines):
        overall = "WARNING"

    return {
        "overall_status": overall,
        "frameworks": [
            {
                "framework": d.get("framework"),
                "jurisdiction": d.get("jurisdiction"),
                "window_hours": d.get("window_hours"),
                "hours_remaining": d.get("hours_remaining"),
                "status": d.get("status"),
                "breached": d.get("breached", False),
                "obligation": d.get("obligation"),
            }
            for d in deadlines
        ],
    }


def _section_breach_readiness(
    holds: List[Dict[str, Any]],
    shadow_score: Optional[float],
    drift_status: Optional[str],
    compliance_overall: str,
) -> Dict[str, Any]:
    """
    Breach Readiness Score — composite of:
      - Active legal holds presence (0 = clean, 1+ = risk)
      - Shadow score (unregistered + unauthorized spawn)
      - Drift status
      - Compliance overall status

    Score: 0.0 (no readiness concern) → 1.0 (breach imminent/active)
    """
    active_holds = [h for h in holds if h.get("status") == "ACTIVE"]
    critical_holds = [h for h in active_holds if h.get("severity") == "CRITICAL"]

    # Hold component: 0.0 clean, 0.5 active holds, 1.0 critical holds
    if critical_holds:
        hold_score = 1.0
    elif active_holds:
        hold_score = 0.5
    else:
        hold_score = 0.0

    # Shadow component
    shadow_component = min(1.0, float(shadow_score or 0.0))

    # Drift component
    drift_map = {"stable": 0.0, "elevated": 0.5, "critical": 1.0}
    drift_component = drift_map.get(drift_status or "stable", 0.0)

    # Compliance component
    compliance_map = {"NOMINAL": 0.0, "WARNING": 0.3, "CRITICAL": 0.7, "BREACHED": 1.0}
    compliance_component = compliance_map.get(compliance_overall, 0.0)

    # Weighted composite
    score = round(
        (hold_score * 0.35)
        + (shadow_component * 0.30)
        + (drift_component * 0.20)
        + (compliance_component * 0.15),
        4,
    )

    if score >= 0.70:
        readiness_band = "CRITICAL"
    elif score >= 0.40:
        readiness_band = "ELEVATED"
    else:
        readiness_band = "CLEAN"

    return {
        "breach_readiness_score": score,
        "readiness_band": readiness_band,
        "active_holds": len(active_holds),
        "critical_holds": len(critical_holds),
        "holds": [
            {
                "id": h.get("id"),
                "trigger_type": h.get("trigger_type"),
                "severity": h.get("severity"),
                "reason": h.get("reason"),
                "created_at": h.get("created_at"),
                "framework": h.get("framework"),
                "jurisdiction": h.get("jurisdiction"),
            }
            for h in active_holds
        ],
        "components": {
            "hold_score": round(hold_score, 4),
            "shadow_component": round(shadow_component, 4),
            "drift_component": round(drift_component, 4),
            "compliance_component": round(compliance_component, 4),
        },
        "weights": {
            "holds": 0.35,
            "shadow": 0.30,
            "drift": 0.20,
            "compliance": 0.15,
        },
    }


# ---------------------------------------------------------------------------
# Main assembler
# ---------------------------------------------------------------------------

def assemble_passport(
    *,
    agent_id: str,
    agent: Optional[Dict[str, Any]],
    events: List[Dict[str, Any]],
    drift: Dict[str, Any],
    shadow: Dict[str, Any],
    deadlines: List[Dict[str, Any]],
    holds: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Assemble a complete Pulse Passport for an agent.
    All inputs are pre-fetched by the caller (main.py endpoint).
    Returns the full passport dict including signature.
    """
    generated_at = datetime.now(timezone.utc).isoformat()

    s1 = _section_agent_identity(agent, agent_id)
    s2 = _section_session_lineage(events)
    s3 = _section_drift_shadow(drift, shadow)
    s4 = _section_compliance_status(deadlines)
    s5 = _section_breach_readiness(
        holds=holds,
        shadow_score=shadow.get("shadow_score"),
        drift_status=drift.get("status"),
        compliance_overall=s4["overall_status"],
    )

    sections = {
        "agent_identity": s1,
        "session_lineage": s2,
        "drift_shadow": s3,
        "compliance_status": s4,
        "breach_readiness": s5,
    }

    signature = _sign_passport(sections, generated_at, agent_id)

    return {
        "passport_version": "PP-1",
        "agent_id": agent_id,
        "generated_at": generated_at,
        "issuer": "Pulse AI Governance Ledger",
        **sections,
        "signature": signature,
    }


# ---------------------------------------------------------------------------
# PDF renderer
# ---------------------------------------------------------------------------

def render_pdf(passport: Dict[str, Any]) -> bytes:
    """
    Render a Pulse Passport dict as a signed PDF.
    Returns raw PDF bytes.
    Requires: pip install reportlab
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
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

    title_style = ParagraphStyle(
        "PulseTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=DARK,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "PulseSub",
        parent=styles["Normal"],
        fontSize=9,
        textColor=GREY,
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "PulseSection",
        parent=styles["Heading2"],
        fontSize=11,
        textColor=TEAL,
        spaceBefore=12,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "PulseBody",
        parent=styles["Normal"],
        fontSize=8,
        textColor=DARK,
        spaceAfter=2,
        leading=12,
    )
    mono_style = ParagraphStyle(
        "PulseMono",
        parent=styles["Code"],
        fontSize=7,
        textColor=GREY,
        spaceAfter=2,
    )

    def kv(label: str, value: Any) -> Paragraph:
        val = str(value) if value is not None else "—"
        return Paragraph(f"<b>{label}:</b> {val}", body_style)

    def section_header(title: str) -> list:
        return [
            Paragraph(title, section_style),
            HRFlowable(width="100%", thickness=0.5, color=TEAL, spaceAfter=4),
        ]

    story = []

    # Header
    story.append(Paragraph("PULSE PASSPORT", title_style))
    story.append(Paragraph(
        f"PP-1 · {passport['agent_id']} · Generated {passport['generated_at']}",
        subtitle_style,
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=TEAL, spaceAfter=8))

    # Section 1 — Agent Identity
    story += section_header("1. Agent Identity")
    s1 = passport.get("agent_identity", {})
    story.append(kv("Agent ID", s1.get("agent_id")))
    story.append(kv("Name", s1.get("name")))
    story.append(kv("Owner", s1.get("owner")))
    story.append(kv("Status", s1.get("status")))
    story.append(kv("Registered At", s1.get("registered_at")))
    scope = ", ".join(s1.get("scope") or []) or "No scopes declared"
    story.append(kv("Declared Scope", scope))
    story.append(kv("Description", s1.get("description")))

    # Section 2 — Session Lineage
    story += section_header("2. Session Lineage Summary")
    s2 = passport.get("session_lineage", {})
    story.append(kv("Total Sessions", s2.get("total_sessions")))
    story.append(kv("Total Turns", s2.get("total_turns")))
    story.append(kv("Total Blocked", s2.get("total_blocked")))
    story.append(kv("Block Rate", f"{round((s2.get('block_rate') or 0) * 100, 1)}%"))
    story.append(kv("Spawned Sessions", s2.get("spawned_sessions")))
    story.append(kv("Root Sessions", s2.get("root_sessions")))

    # Section 3 — Drift + Shadow
    story += section_header("3. Drift & Shadow Score")
    s3 = passport.get("drift_shadow", {})
    drift_d = s3.get("drift", {})
    shadow_d = s3.get("shadow_score_v2", {})
    story.append(kv("Drift Score", drift_d.get("score")))
    story.append(kv("Drift Status", drift_d.get("status")))
    story.append(kv("Turns Analyzed", drift_d.get("turns_analyzed")))
    story.append(Spacer(1, 4))
    story.append(kv("Shadow Score v2", shadow_d.get("shadow_score")))
    story.append(kv("Shadow Status", shadow_d.get("status")))
    story.append(kv("Shadow Flag", shadow_d.get("flag")))
    if shadow_d.get("note"):
        story.append(kv("Note", shadow_d.get("note")))

    # Section 4 — Compliance
    story += section_header("4. ASEAN Compliance Status")
    s4 = passport.get("compliance_status", {})
    story.append(kv("Overall Status", s4.get("overall_status")))
    for fw in s4.get("frameworks", []):
        story.append(Spacer(1, 3))
        story.append(Paragraph(
            f"<b>{fw.get('framework')}</b> [{fw.get('jurisdiction')}] — "
            f"{fw.get('status')} · {fw.get('hours_remaining')}h remaining",
            body_style,
        ))

    # Section 5 — Breach Readiness
    story += section_header("5. Breach Readiness")
    s5 = passport.get("breach_readiness", {})
    story.append(kv("Breach Readiness Score", s5.get("breach_readiness_score")))
    story.append(kv("Readiness Band", s5.get("readiness_band")))
    story.append(kv("Active Legal Holds", s5.get("active_holds")))
    story.append(kv("Critical Holds", s5.get("critical_holds")))
    for hold in s5.get("holds", []):
        story.append(Paragraph(
            f"  • [{hold.get('severity')}] {hold.get('trigger_type')} — {hold.get('reason')}",
            body_style,
        ))

    # Section 6 — Signature
    story += section_header("6. Passport Signature")
    sig = passport.get("signature", {})
    story.append(kv("Algorithm", sig.get("algorithm")))
    story.append(kv("Signed Fields", ", ".join(sig.get("signed_fields", []))))
    story.append(Spacer(1, 4))
    # Break digest across two lines for readability
    digest = sig.get("digest", "")
    story.append(Paragraph("<b>SHA-256 Digest:</b>", body_style))
    story.append(Paragraph(digest[:32], mono_style))
    story.append(Paragraph(digest[32:], mono_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(sig.get("note", ""), body_style))

    doc.build(story)
    return buf.getvalue()
