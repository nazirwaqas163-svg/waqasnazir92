"""Low-rate, clearly tagged production event-ledger soak check.

Requires PULSE_ORG_API_KEY to be supplied by the caller (for example, a
GitHub Actions secret). Never prints credentials or sends real user data.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

DEFAULT_BASE_URL = "https://pulse-proxy-8dqx.onrender.com"
AGENT_ID = "synthetic-soak-runner"
MARKER = "synthetic_soak"
MAX_EVENTS_PER_RUN = 10


class ProbeError(RuntimeError):
    """An expected API or verification failure with a safe-to-print message."""


def request_json(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    api_key: str | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}", data=body, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=35) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Do not echo request headers or tokens in errors or GitHub summaries.
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail", "")
        except (ValueError, AttributeError):
            detail = ""
        raise ProbeError(f"{method} {path} returned HTTP {exc.code}: {detail}") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ProbeError(f"{method} {path} failed: {type(exc).__name__}") from None
    if not isinstance(result, dict):
        raise ProbeError(f"{method} {path} returned an unexpected response")
    return result


def parse_start_at(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("start-at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("start-at must include a timezone")
    return parsed.astimezone(timezone.utc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-at", type=parse_start_at, required=True)
    parser.add_argument("--count", type=int, default=MAX_EVENTS_PER_RUN)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.count <= MAX_EVENTS_PER_RUN:
        parser.error(f"count must be between 1 and {MAX_EVENTS_PER_RUN}")

    now = datetime.now(timezone.utc)
    stop_at = args.start_at + timedelta(days=7)
    if now >= stop_at:
        print(f"SOAK_COMPLETE stop_at={stop_at.isoformat()} events_sent=0")
        return 0

    run_id = os.environ.get("GITHUB_RUN_ID") or f"manual-{uuid.uuid4().hex[:12]}"
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    expected_ids: set[str] = set()
    print(
        f"SOAK_START start_at={args.start_at.isoformat()} stop_at={stop_at.isoformat()} "
        f"batch_size={args.count} marker={MARKER}"
    )

    if args.dry_run:
        for sequence in range(1, args.count + 1):
            print(f"DRY_RUN event={sequence} agent_id={AGENT_ID} action={MARKER}")
        print(f"DRY_RUN_COMPLETE count={args.count}; no requests sent")
        return 0

    api_key = os.environ.get("PULSE_ORG_API_KEY", "").strip()
    if not api_key:
        print("SOAK_SKIPPED: configure the PULSE_ORG_API_KEY repository secret")
        return 0

    base_url = os.environ.get("PULSE_API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    parsed_url = urllib.parse.urlparse(base_url)
    if parsed_url.scheme != "https" or parsed_url.hostname != "pulse-proxy-8dqx.onrender.com":
        print("SOAK_FAILED: refusing to send production credentials to an unapproved host", file=sys.stderr)
        return 2

    latencies: list[float] = []
    batch_session_id = f"{MARKER}:{run_id}:{run_attempt}"
    try:
        for sequence in range(1, args.count + 1):
            payload = {
                "agent_id": AGENT_ID,
                "session_id": batch_session_id,
                "input_text": f"SYNTHETIC_SOAK service reliability check {sequence}; no user data.",
                "output_text": f"Synthetic governance probe {sequence} completed.",
                "metadata": {
                    "operation": MARKER,
                    "synthetic_test": True,
                    "run_id": run_id,
                    "run_attempt": run_attempt,
                    "sequence": sequence,
                },
                "bdi_score": 0.01,
                "entropy": 0.01,
                "self_reported_risk": 0.01,
            }
            request_started = time.monotonic()
            response = request_json(
                base_url,
                "/intercept",
                method="POST",
                api_key=api_key,
                payload=payload,
            )
            if response.get("ok") is not True or response.get("allowed") is not True:
                raise ProbeError(f"synthetic event {sequence} was not allowed")
            request_id = response.get("request_id")
            if not isinstance(request_id, str) or not request_id:
                raise ProbeError(f"synthetic event {sequence} returned no request ID")
            expected_ids.add(request_id)
            latency = time.monotonic() - request_started
            latencies.append(latency)
            print(f"EVENT_ACCEPTED sequence={sequence} request_id={request_id} latency_seconds={latency:.3f}")
            if sequence < args.count:
                time.sleep(1)

        query = urllib.parse.urlencode({"limit": 500})
        ledger = request_json(
            base_url,
            f"/ai_events/recent?{query}",
            api_key=api_key,
        )
        rows = ledger.get("events")
        if not isinstance(rows, list):
            raise ProbeError("recent-events endpoint returned no event list")
        visible_ids = {
            row.get("event_id")
            for row in rows
            if isinstance(row, dict)
            and row.get("agent_id") == AGENT_ID
            and row.get("action") == MARKER
        }
        missing = expected_ids - visible_ids
        if missing:
            raise ProbeError(
                f"read-back verification missing {len(missing)} of {len(expected_ids)} newly accepted events"
            )

        health = request_json(base_url, "/health")
        average_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[min(len(latencies) - 1, int(len(latencies) * 0.95))]
        print(
            f"SOAK_PASS accepted={len(expected_ids)} verified={len(expected_ids)} "
            f"visible_recent_events={len(rows)} health={health.get('status', 'unknown')} "
            f"ready={health.get('ready', 'unknown')} average_latency_seconds={average_latency:.3f} "
            f"p95_latency_seconds={p95_latency:.3f}"
        )
        return 0
    except ProbeError as exc:
        print(f"SOAK_FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

