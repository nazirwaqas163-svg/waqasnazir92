"""
Dashboard Topology — Phase 3 Stage 5.

Pure assembler that turns a flat list of ai_events into the node/edge graph the
dashboard renders:

  nodes:  agent nodes  + session nodes
  edges:  agent --owns--> session
          session --spawned--> session   (via parent_session_id, Stage 2)

Each session node carries its drift status (looked up live) and a derived
risk_band so the frontend can colour the graph without extra calls.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


def _session_band(node: Dict[str, Any]) -> str:
    drift_status = node.get("drift_status")
    if drift_status == "critical":
        return "critical"
    turns = node.get("turns") or 0
    blocked_ratio = (node.get("blocked") or 0) / turns if turns else 0.0
    if drift_status == "elevated" or blocked_ratio >= 0.5:
        return "elevated"
    if blocked_ratio > 0:
        return "caution"
    return "stable"


def _agent_band(node: Dict[str, Any]) -> str:
    events = node.get("events") or 0
    blocked_ratio = (node.get("blocked") or 0) / events if events else 0.0
    if not node.get("registered"):
        return "unregistered"
    if blocked_ratio >= 0.5:
        return "critical"
    if blocked_ratio > 0:
        return "elevated"
    return "stable"


def build_topology(
    events: List[Dict[str, Any]],
    agents: Optional[List[Dict[str, Any]]] = None,
    drift_lookup: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    registered = {a.get("agent_id") for a in (agents or [])}
    drift_lookup = drift_lookup or (lambda _sid: None)

    agent_nodes: Dict[str, Dict[str, Any]] = {}
    session_nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    edge_seen: set = set()

    for e in events:
        aid = e.get("agent_id") or "unknown"
        sid = e.get("session_id")
        pid = e.get("parent_session_id")
        blocked = e.get("status") == "blocked"

        an = agent_nodes.setdefault(
            aid,
            {
                "id": f"agent:{aid}",
                "label": aid,
                "type": "agent",
                "agent_id": aid,
                "registered": aid in registered,
                "events": 0,
                "blocked": 0,
            },
        )
        an["events"] += 1
        if blocked:
            an["blocked"] += 1

        if not sid:
            continue

        sn = session_nodes.setdefault(
            sid,
            {
                "id": f"session:{sid}",
                "label": sid,
                "type": "session",
                "session_id": sid,
                "agent_id": aid,
                "parent_session_id": pid,
                "turns": 0,
                "blocked": 0,
            },
        )
        sn["turns"] += 1
        if blocked:
            sn["blocked"] += 1
        if pid and not sn.get("parent_session_id"):
            sn["parent_session_id"] = pid

        ek = (an["id"], sn["id"], "owns")
        if ek not in edge_seen:
            edge_seen.add(ek)
            edges.append({"source": an["id"], "target": sn["id"], "type": "owns"})

    for sid, sn in session_nodes.items():
        pid = sn.get("parent_session_id")
        if pid and pid in session_nodes:
            ek = (f"session:{pid}", sn["id"], "spawned")
            if ek not in edge_seen:
                edge_seen.add(ek)
                edges.append({"source": f"session:{pid}", "target": sn["id"], "type": "spawned"})
        drift = drift_lookup(sid) or {}
        sn["drift_status"] = drift.get("status", "unknown")
        sn["drift_score"] = drift.get("score")
        sn["risk_band"] = _session_band(sn)

    for an in agent_nodes.values():
        an["risk_band"] = _agent_band(an)

    nodes = list(agent_nodes.values()) + list(session_nodes.values())
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "agents": len(agent_nodes),
            "sessions": len(session_nodes),
            "edges": len(edges),
            "unregistered_agents": sum(1 for a in agent_nodes.values() if not a["registered"]),
            "critical_sessions": sum(1 for s in session_nodes.values() if s["risk_band"] == "critical"),
        },
        "nodes": nodes,
        "edges": edges,
    }
