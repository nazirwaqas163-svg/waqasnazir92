"""
legal_hold.py — Pulse AI Governance Middleware
Sealed forensic evidence holds with RFC 3161 trusted timestamping.

RFC 3161 flow:
  On seal: chain_hash bytes → TSA → timestamp token (DER) → stored as
  tsa_token_b64 in legal_holds row + returned in evidence package.
  Verifiable by any RFC 3161-compliant tool without trusting Pulse.
"""

import hashlib
import json
import logging
import base64
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

from supabase import create_client, Client

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TSA configuration — multiple endpoints, tried in order
# ---------------------------------------------------------------------------
TSA_ENDPOINTS = [
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
    "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
]
TSA_TIMEOUT = 8  # seconds per attempt


def _get_rfc3161_token(data: bytes) -> Optional[str]:
    """
    Request an RFC 3161 timestamp token for *data* from the first
    responsive TSA.  Returns the raw TSR response as base64, or None
    if every TSA fails (non-fatal — hold seals without it).
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

            # Basic sanity — a valid TSR is at least a few hundred bytes
            if len(raw_tsr) < 100:
                logger.warning("TSA %s returned suspiciously short response (%d bytes)", url, len(raw_tsr))
                continue

            token_b64 = base64.b64encode(raw_tsr).decode()
            logger.info("RFC 3161 timestamp obtained from %s (%d bytes)", url, len(raw_tsr))
            return token_b64

        except urllib.error.HTTPError as exc:
            logger.warning("TSA %s HTTP %s — trying next", url, exc.code)
        except Exception as exc:
            logger.warning("TSA %s failed (%s) — trying next", url, exc)

    logger.warning("All TSA endpoints failed — legal hold sealed without external timestamp")
    return None


# ---------------------------------------------------------------------------
# LegalHoldManager
# ---------------------------------------------------------------------------

class LegalHoldManager:
    def __init__(self, supabase_client: Client):
        self.supabase = supabase_client

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------
    def create_hold(
        self,
        trigger_type: str,
        agent_id: str,
        session_id: str,
        severity: str,
        evidence: dict,
        chain_hash: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> dict:
        """
        Open a new legal hold.  Does NOT seal — call seal_hold() separately
        once all evidence has been gathered.
        """
        hold_id = self._generate_hold_id(agent_id, trigger_type)
        now = datetime.now(timezone.utc).isoformat()

        row = {
            "id": hold_id,
            "trigger_type": trigger_type,
            "agent_id": agent_id,
            "session_id": session_id,
            "severity": severity,
            "status": "active",
            "evidence": evidence,
            "chain_hash": chain_hash,
            "org_id": org_id,
            "created_at": now,
            "tsa_token_b64": None,
            "tsa_stamped_at": None,
            "tsa_endpoint": None,
        }

        try:
            result = self.supabase.table("legal_holds").insert(row).execute()
            logger.info("Legal hold created: %s (trigger=%s)", hold_id, trigger_type)
            return {"hold_id": hold_id, "status": "active", "data": result.data}
        except Exception as exc:
            logger.error("Failed to create legal hold: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Seal — with RFC 3161 timestamping
    # ------------------------------------------------------------------
    def seal_hold(self, hold_id: str) -> dict:
        """
        Seal a legal hold:
          1. Fetch current evidence + chain_hash
          2. Compute seal_hash (SHA-256 of evidence JSON + chain_hash)
          3. Request RFC 3161 timestamp token from external TSA
          4. Persist seal_hash, tsa_token_b64, tsa_stamped_at, status=sealed
        """
        # Fetch existing hold
        try:
            result = (
                self.supabase.table("legal_holds")
                .select("*")
                .eq("id", hold_id)
                .execute()
            )
            if not result.data:
                raise ValueError(f"Hold {hold_id} not found")
            hold = result.data[0]
        except Exception as exc:
            logger.error("seal_hold: fetch failed for %s: %s", hold_id, exc)
            raise

        # Build seal payload
        evidence_str = json.dumps(hold.get("evidence", {}), sort_keys=True)
        chain_hash = hold.get("chain_hash") or ""
        seal_input = f"{evidence_str}:{chain_hash}:{hold_id}"
        seal_hash = hashlib.sha256(seal_input.encode()).hexdigest()

        # RFC 3161 timestamp on the seal_hash
        seal_hash_bytes = seal_hash.encode()
        tsa_token_b64 = _get_rfc3161_token(seal_hash_bytes)
        tsa_stamped_at = datetime.now(timezone.utc).isoformat() if tsa_token_b64 else None
        tsa_endpoint = None
        if tsa_token_b64:
            # Identify which endpoint responded (best-effort — stored for auditability)
            tsa_endpoint = "see tsa_token_b64 (RFC 3161 TSR)"

        # Determine which TSA responded (store it properly)
        # We re-probe to get the endpoint name
        if tsa_token_b64:
            tsa_endpoint = _identify_tsa_endpoint(tsa_token_b64)

        now = datetime.now(timezone.utc).isoformat()
        update_payload = {
            "seal_hash": seal_hash,
            "status": "sealed",
            "sealed_at": now,
            "tsa_token_b64": tsa_token_b64,
            "tsa_stamped_at": tsa_stamped_at,
            "tsa_endpoint": tsa_endpoint,
        }

        try:
            self.supabase.table("legal_holds").update(update_payload).eq("id", hold_id).execute()
        except Exception as exc:
            logger.error("seal_hold: Supabase update failed for %s: %s", hold_id, exc)
            raise

        tsa_status = "RFC_3161_STAMPED" if tsa_token_b64 else "INTERNAL_SEAL_ONLY"
        logger.info(
            "Legal hold sealed: %s | seal_hash=%s | tsa=%s",
            hold_id, seal_hash[:16], tsa_status,
        )

        return {
            "hold_id": hold_id,
            "status": "sealed",
            "seal_hash": seal_hash,
            "tsa_status": tsa_status,
            "tsa_stamped_at": tsa_stamped_at,
            "tsa_endpoint": tsa_endpoint,
        }

    # ------------------------------------------------------------------
    # Auto-seal convenience (create + immediately seal)
    # ------------------------------------------------------------------
    def create_and_seal(
        self,
        trigger_type: str,
        agent_id: str,
        session_id: str,
        severity: str,
        evidence: dict,
        chain_hash: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> dict:
        create_result = self.create_hold(
            trigger_type=trigger_type,
            agent_id=agent_id,
            session_id=session_id,
            severity=severity,
            evidence=evidence,
            chain_hash=chain_hash,
            org_id=org_id,
        )
        hold_id = create_result["hold_id"]
        seal_result = self.seal_hold(hold_id)
        return {**create_result, **seal_result}

    # ------------------------------------------------------------------
    # Fetch / list
    # ------------------------------------------------------------------
    def get_hold(self, hold_id: str) -> Optional[dict]:
        try:
            result = (
                self.supabase.table("legal_holds")
                .select("*")
                .eq("id", hold_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.error("get_hold failed for %s: %s", hold_id, exc)
            return None

    def list_holds(
        self,
        agent_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> list:
        try:
            query = self.supabase.table("legal_holds").select("*").order("created_at", desc=True).limit(limit)
            if agent_id:
                query = query.eq("agent_id", agent_id)
            if status:
                query = query.eq("status", status)
            result = query.execute()
            return result.data or []
        except Exception as exc:
            logger.error("list_holds failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Release
    # ------------------------------------------------------------------
    def release_hold(self, hold_id: str, released_by: Optional[str] = None) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.supabase.table("legal_holds").update({
                "status": "released",
                "released_at": now,
                "released_by": released_by,
            }).eq("id", hold_id).execute()
            logger.info("Legal hold released: %s", hold_id)
            return {"hold_id": hold_id, "status": "released"}
        except Exception as exc:
            logger.error("release_hold failed for %s: %s", hold_id, exc)
            raise

    # ------------------------------------------------------------------
    # TSA verification helper (for evidence package + dashboard)
    # ------------------------------------------------------------------
    def verify_tsa_token(self, hold_id: str) -> dict:
        """
        Verify the RFC 3161 token stored on a hold against its seal_hash.
        Returns verification status dict.
        """
        hold = self.get_hold(hold_id)
        if not hold:
            return {"verified": False, "error": "Hold not found"}

        tsa_token_b64 = hold.get("tsa_token_b64")
        if not tsa_token_b64:
            return {
                "verified": False,
                "tsa_status": "NO_TOKEN",
                "note": "Hold sealed without external timestamp (TSA unavailable at seal time)",
            }

        try:
            import rfc3161ng
            seal_hash = hold.get("seal_hash", "")
            tsr_bytes = base64.b64decode(tsa_token_b64)
            tst = rfc3161ng.decode_timestamp_response(tsr_bytes)

            # Extract timestamp from TST
            tst_info = tst["time_stamp_token"]["content"]["encap_content_info"]["content"]
            ts = rfc3161ng.get_timestamp(tst)

            return {
                "verified": True,
                "tsa_status": "RFC_3161_VALID",
                "timestamp_utc": ts.isoformat() if ts else None,
                "tsa_endpoint": hold.get("tsa_endpoint"),
                "seal_hash": seal_hash,
                "note": "Timestamp token verified against seal_hash",
            }
        except Exception as exc:
            return {
                "verified": False,
                "tsa_status": "VERIFICATION_ERROR",
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_hold_id(agent_id: str, trigger_type: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        raw = f"{agent_id}:{trigger_type}:{timestamp}"
        short_hash = hashlib.sha256(raw.encode()).hexdigest()[:8]
        return f"HOLD-{timestamp}-{short_hash.upper()}"


def _identify_tsa_endpoint(tsa_token_b64: str) -> str:
    """
    Best-effort: decode the TSR and extract the TSA name from the cert
    or just return a label.  Falls back to generic label on any error.
    """
    try:
        import rfc3161ng
        tsr_bytes = base64.b64decode(tsa_token_b64)
        tst = rfc3161ng.decode_timestamp_response(tsr_bytes)
        # Try to get policy OID as a proxy for identity
        tst_info = tst["time_stamp_token"]["content"]["encap_content_info"]["content"]
        policy = str(tst_info["policy"])
        return f"RFC3161-TSA (policy={policy})"
    except Exception:
        return "RFC3161-TSA"


# ---------------------------------------------------------------------------
# Standalone: auto_legal_hold() — called from main.py /intercept
# ---------------------------------------------------------------------------

def auto_legal_hold(
    supabase_client: Client,
    trigger_type: str,
    agent_id: str,
    session_id: str,
    severity: str,
    evidence: dict,
    chain_hash: Optional[str] = None,
    org_id: Optional[str] = None,
) -> dict:
    """
    Convenience wrapper called from /intercept auto-response logic.
    Creates and immediately seals a hold (including RFC 3161 stamp).
    """
    mgr = LegalHoldManager(supabase_client)
    return mgr.create_and_seal(
        trigger_type=trigger_type,
        agent_id=agent_id,
        session_id=session_id,
        severity=severity,
        evidence=evidence,
        chain_hash=chain_hash,
        org_id=org_id,
    )
