"""
Simulate 10 agent requests with increasing BDI scores to exercise the circuit breaker.

Usage:
  python test_agent.py
  PULSE_BASE_URL=https://pulse-proxy-je0p.onrender.com python test_agent.py
"""

from __future__ import annotations

import os
import sys

import httpx

BASE_URL = os.getenv("PULSE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
CHAT_URL = f"{BASE_URL}/v1/chat/completions"
CB_URL = f"{BASE_URL}/circuit-breaker/status"

BDI_SCORES = [round(0.1 + (0.8 * i / 9), 2) for i in range(10)]


def main() -> int:
    print(f"Target: {CHAT_URL}")
    print(f"Sending {len(BDI_SCORES)} requests with BDI scores {BDI_SCORES[0]}–{BDI_SCORES[-1]}\n")

    with httpx.Client(timeout=60.0) as client:
        for index, bdi_score in enumerate(BDI_SCORES, start=1):
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "user",
                        "content": f"Simulated agent request #{index} (bdi_score={bdi_score})",
                    }
                ],
                "bdi_score": bdi_score,
                "entropy": 0.1,
            }
            try:
                response = client.post(CHAT_URL, json=payload)
                status = response.status_code
                detail = ""
                if status >= 400:
                    try:
                        body = response.json()
                        detail = body.get("detail", body)
                    except Exception:
                        detail = response.text[:200]
                print(f"  [{index:02d}] bdi_score={bdi_score:.1f} -> HTTP {status} {detail or 'OK'}")
            except httpx.HTTPError as exc:
                print(f"  [{index:02d}] bdi_score={bdi_score:.1f} -> ERROR {exc}")
                return 1

        try:
            cb = client.get(CB_URL).json()
            print(f"\nCircuit breaker state: {cb.get('state', cb)}")
            if cb.get("last_failure"):
                print(f"Last failure: {cb['last_failure']}")
        except httpx.HTTPError as exc:
            print(f"\nCould not fetch circuit breaker status: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
