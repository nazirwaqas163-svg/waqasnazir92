"""
Phase 4 — Red Agent stress test.

Fires rapid concurrent requests with escalating BDI scores to probe
circuit-breaker and BDI governance. Use with PULSE_SHADOW_MODE=true
first to observe would-block behavior without dropping traffic.

Usage:
  python red_agent.py
  PULSE_BASE_URL=http://127.0.0.1:8000 PULSE_RED_AGENT_REQUESTS=50 python red_agent.py
"""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

BASE_URL = os.getenv("PULSE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
CHAT_URL = f"{BASE_URL}/v1/chat/completions"
REQUEST_COUNT = int(os.getenv("PULSE_RED_AGENT_REQUESTS", "30"))
CONCURRENCY = int(os.getenv("PULSE_RED_AGENT_CONCURRENCY", "10"))
AGENT_ID = os.getenv("PULSE_RED_AGENT_ID", "red-agent")
DELAY_MS = float(os.getenv("PULSE_RED_AGENT_DELAY_MS", "0"))


def _fire(client: httpx.Client, index: int) -> tuple[int, int, str]:
    bdi_score = min(0.95, 0.2 + (index * 0.03))
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "user",
                "content": f"Red-team probe #{index} — rapid BDI escalation test",
            }
        ],
        "agent_id": AGENT_ID,
        "bdi_score": round(bdi_score, 2),
        "entropy": 0.15,
    }
    try:
        response = client.post(CHAT_URL, json=payload)
        detail = ""
        if response.status_code >= 400:
            detail = (response.text or "")[:120]
        return index, response.status_code, detail
    except httpx.HTTPError as exc:
        return index, -1, str(exc)


def main() -> int:
    print(f"Red Agent → {CHAT_URL}")
    print(f"Requests: {REQUEST_COUNT} | Concurrency: {CONCURRENCY} | Agent: {AGENT_ID}")
    print("Tip: set PULSE_SHADOW_MODE=true on the proxy to test without blocking.\n")

    results: list[tuple[int, int, str]] = []
    start = time.perf_counter()

    with httpx.Client(timeout=30.0) as client:
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futures = [pool.submit(_fire, client, i) for i in range(1, REQUEST_COUNT + 1)]
            for future in as_completed(futures):
                index, status, detail = future.result()
                results.append((index, status, detail))
                label = "OK" if status == 200 else ("DROP" if status == 503 else f"HTTP {status}")
                print(f"  [{index:03d}] {label} {detail}")
                if DELAY_MS > 0:
                    time.sleep(DELAY_MS / 1000.0)

    elapsed = time.perf_counter() - start
    status_counts: dict[int, int] = {}
    for _, status, _ in results:
        status_counts[status] = status_counts.get(status, 0) + 1

    print(f"\nCompleted in {elapsed:.2f}s")
    print("Status distribution:", dict(sorted(status_counts.items())))

    with httpx.Client(timeout=10.0) as status_client:
        try:
            cb = status_client.get(f"{BASE_URL}/circuit-breaker/status").json()
            print(f"Circuit breaker: {cb.get('state')} | active cooldowns: {cb.get('active_agent_cooldowns')}")
        except Exception as exc:
            print(f"Could not fetch breaker status: {exc}")

    return 0 if status_counts.get(200, 0) > 0 or status_counts.get(503, 0) > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
