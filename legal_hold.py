"""
legal_hold.py — Pulse AI Governance Middleware
Same interface as before. RFC 3161 trusted timestamping added on seal.
"""

import hashlib
import json
import logging
import base64
import urllib.request
import urllib.error
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TSA endpoints — tried in order, first success wins
# ---------------------------------------------------------------------------
TSA_ENDPOINTS = [
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
    "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
]
TSA_TIMEOUT = 8


def _get_rfc3161_token(data: bytes) -> Optional[str]:
    """
    Request an RFC 3161 timestamp token from the first responsive TSA.
    Returns base64-encoded TSR, or None if all TSAs fail (non-fatal).
    """
    try:
        import rfc3161ng
    except ImportError:
        logger.warning("rfc3161ng not installed — skipping trusted timestamp")
        return None

    try:
        req_obj = rfc3161ng.make_timestamp_request(
            data=data, hashname="sha256", include_tsa_certificate=True
        )
        encoded = rfc3161ng.encode_timestamp_request(req_obj)
    except Exception as exc:
        logger.warning("RFC 3161 request build failed: %s", exc)
        return None

    for url in TSA_ENDPOINTS:
        try:
            http_req = urllib.request.Request(
                url,
                data=encoded,
                headers={"Content-Type": "application/timestamp-query"},
            )
            with urllib.request.urlopen(http_req, timeout=TSA_TIMEOUT) as resp:
                raw_tsr = resp.read()
            if len(raw_tsr) < 100:
                continue
            token_b64 = base64.b64encode(raw_tsr).decode()
            logger.info("RFC 3161 timestamp obtained from %s (%d bytes)", url, len(raw_tsr))
            return token_b64
        except urllib.error.HTTPError as exc:
            logger.warning("TSA %s HTTP %s", url, exc.code)
        except Exception as exc:
            logger.warning("TSA %s failed: %s", url, exc)

    logger.warning("All TSA endpoints failed — hold sealed without external timestamp")
    return None


def _compute_seal_hash(hold: Dict[str, Any]) -> str:
    evidence_str = json.dumps(hold.get("evidence") or {}, sort_keys=True)
    chain_hash = hold.get("chain_hash") or ""
    hold_id = hold.get("id") or ""
    seal_input = f"{evidence_str}:{chain_hash}:{hold_id}"
    return hashlib.sha256(seal_input.encode()).hexdigest()


# ---------------------------------------------------------------------------
# LegalHoldManager — same interface as before
# ---------------------------------------------------------------------------

class LegalHoldManager:
    def __init__(self) -> None:
        self._holds: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()

    def create(
        self,
        *,
        trigger_type: str,
        reason: str,
        severity: str = "HIGH",
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        event_id: Optional[str] = None,
        chain_hash: Optional[str] = None,
        framework: Optional[str] = None,
        jurisdiction: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        dedupe_scope: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Create a new legal hold, compute seal hash, and request an
        RFC 3161 timestamp token from an external TSA.
        Returns None if a duplicate active hold already exists.
        """
        with self._lock:
            # Deduplicate
            dedupe_key = dedupe_scope or f"{trigger_type}:{agent_id}:{session_id}"
            for h in self._holds.values():
                if (
                    h.get("status") == "ACTIVE"
                    and h.get("_dedupe_key") == dedupe_key
                ):
                    return None

            hold_id = self._generate_id(agent_id, trigger_type)
            now = datetime.now(timezone.utc).isoformat()

            hold: Dict[str, Any] = {
                "id": hold_id,
                "trigger_type": trigger_type,
                "reason": reason,
                "severity": severity.upper(),
                "status": "ACTIVE",
                "agent_id": agent_id,
                "session_id": session_id,
                "event_id": event_id,
                "chain_hash": chain_hash,
                "framework": framework,
                "jurisdiction": jurisdiction,
                "evidence": evidence or {},
                "created_at": now,
                "released_at": None,
                "released_by": None,
                "_dedupe_key": dedupe_key,
                # RFC 3161 fields
                "seal_hash": None,
                "tsa_token_b64": None,
                "tsa_stamped_at": None,
                "tsa_endpoint": None,
                "tsa_status": "PENDING",
            }

            # Compute seal hash
            seal_hash = _compute_seal_hash(hold)
            hold["seal_hash"] = seal_hash

            # Request RFC 3161 timestamp (non-blocking on failure)
            tsa_token_b64 = _get_rfc3161_token(seal_hash.encode())
            if tsa_token_b64:
                hold["tsa_token_b64"] = tsa_token_b64
                hold["tsa_stamped_at"] = datetime.now(timezone.utc).isoformat()
                hold["tsa_endpoint"] = "RFC3161-TSA"
                hold["tsa_status"] = "RFC_3161_STAMPED"
            else:
                hold["tsa_status"] = "INTERNAL_SEAL_ONLY"

            self._holds[hold_id] = hold
            logger.info(
                "Legal hold created: %s | trigger=%s | tsa=%s",
                hold_id, trigger_type, hold["tsa_status"],
            )
            return hold

    def get(self, hold_id: str) -> Optional[Dict[str, Any]]:
        return self._holds.get(hold_id)

    def list(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            holds = [
                {k: v for k, v in h.items() if not k.startswith("_")}
                for h in self._holds.values()
            ]
        if status:
            holds = [h for h in holds if h.get("status", "").upper() == status.upper()]
        holds.sort(key=lambda h: h.get("created_at") or "", reverse=True)
        return holds[:limit]

    def release(
        self,
        hold_id: str,
        released_by: str = "dashboard",
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            hold = self._holds.get(hold_id)
            if hold is None:
                return None
            hold["status"] = "RELEASED"
            hold["released_at"] = datetime.now(timezone.utc).isoformat()
            hold["released_by"] = released_by
            return {k: v for k, v in hold.items() if not k.startswith("_")}

    def reset(self) -> None:
        with self._lock:
            self._holds.clear()

    @staticmethod
    def _generate_id(agent_id: Optional[str], trigger_type: str) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        raw = f"{agent_id}:{trigger_type}:{ts}"
        short = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
        return f"HOLD-{ts}-{short}"


# ---------------------------------------------------------------------------
# Module-level singleton — imported by main.py as legal_hold_manager
# ---------------------------------------------------------------------------
legal_hold_manager = LegalHoldManager()


# ---------------------------------------------------------------------------
# evaluate_triggers — same signature as before
# ---------------------------------------------------------------------------

def evaluate_triggers(
    *,
    drift_result: Optional[Dict[str, Any]] = None,
    shadow: Optional[Dict[str, Any]] = None,
    swarm: Optional[Dict[str, Any]] = None,
    deadlines: Optional[List[Dict[str, Any]]] = None,
    exfiltration: Optional[Dict[str, Any]] = None,
    policy_violations: Optional[List[Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluate governance signals and return a list of hold trigger dicts.
    Each trigger dict has: trigger_type, reason, severity, framework,
    jurisdiction, dedupe_scope.
    """
    triggers: List[Dict[str, Any]] = []

    # Exfiltration
    if exfiltration and exfiltration.get("alert"):
        risk = exfiltration.get("risk_score", 0.0)
        triggers.append({
            "trigger_type": "exfiltration",
            "reason": f"Exfiltration risk detected (score={risk:.3f})",
            "severity": "CRITICAL",
            "framework": "PDPA Malaysia / Singapore MGF / Vietnam AI Law",
            "jurisdiction": "ASEAN",
            "dedupe_scope": None,
        })

    # Org policy violations
    if policy_violations:
        names = ", ".join(
            v.get("policy_name", v.get("name", "unknown"))
            for v in policy_violations
            if isinstance(v, dict)
        )
        triggers.append({
            "trigger_type": "policy_violation",
            "reason": f"Org policy violation: {names or len(policy_violations)} rule(s) fired",
            "severity": "HIGH",
            "framework": "Company Policy",
            "jurisdiction": "ORG",
            "dedupe_scope": None,
        })

    # Swarm detection
    if swarm and swarm.get("swarm_suspect"):
        count = swarm.get("active_sessions", 0)
        triggers.append({
            "trigger_type": "swarm",
            "reason": f"Swarm activity detected ({count} concurrent sessions)",
            "severity": "CRITICAL",
            "framework": "Singapore Model AI Governance Framework",
            "jurisdiction": "SG",
            "dedupe_scope": None,
        })

    # Critical drift
    if drift_result and drift_result.get("status") == "critical":
        score = drift_result.get("score", 0.0)
        triggers.append({
            "trigger_type": "critical_drift",
            "reason": f"Critical behavioral drift detected (score={score:.3f})",
            "severity": "HIGH",
            "framework": "ISO/IEC 42001",
            "jurisdiction": "INTL",
            "dedupe_scope": None,
        })

    # Shadow score under-reporting
    if shadow and shadow.get("shadow_score_v2") is not None:
        sv2 = shadow.get("shadow_score_v2") or {}
        score = sv2.get("shadow_score", 0.0) if isinstance(sv2, dict) else 0.0
        if score > 0.7:
            triggers.append({
                "trigger_type": "shadow_underreporting",
                "reason": f"Shadow score anomaly detected (score={score:.3f})",
                "severity": "HIGH",
                "framework": "Singapore Model AI Governance Framework",
                "jurisdiction": "SG",
                "dedupe_scope": None,
            })

    # Deadline breaches
    if deadlines:
        for d in deadlines:
            if d.get("breached"):
                triggers.append({
                    "trigger_type": "compliance_breach",
                    "reason": f"{d.get('framework')} reporting deadline breached",
                    "severity": "CRITICAL",
                    "framework": d.get("framework"),
                    "jurisdiction": d.get("jurisdiction"),
                    "dedupe_scope": d.get("framework"),
                })

    return triggers
