# Pulse Governance Ledger — Work Summary

**Project:** AI agent swarm governance platform with circuit breaker kill switch  
**Local path:** `C:\Users\Lenovo\pulse-proxy`  
**Repository:** https://github.com/nazirwaqas163-svg/waqasnazir92  
**Deployed:** https://pulse-proxy-je0p.onrender.com  
**Last updated:** June 8, 2026

---

## Overview

Pulse Governance Ledger is a FastAPI proxy that sits in front of LLM/agent traffic and enforces governance rules: BDI scoring, Shannon entropy checks, deny-by-default tool policies, financial transaction limits, and a manual kill switch. A dark-themed dashboard visualizes live events, and supporting tools simulate and stress-test agent behavior.

---

## What Was Built (Chronological)

### Foundation — Initial Proxy

- FastAPI backend (`main.py`) proxying `POST /v1/chat/completions` to an upstream LLM (or baseline fallback when no API key is set)
- BDI state tracking (`bdi.py`) — beliefs, desires, intentions from conversation turns
- In-memory event feed (`pulse_feed.py`) with embeddings and novelty scoring
- Refusal detection, financial transaction blocking (>$5,000), and Shannon entropy calculation
- `GET /health`, `GET /events`, `GET /pulse`, `POST /pulse/reset`
- Frontend static dashboard (`frontend/index.html` + `frontend/server.py` on port 8080)
- Deployed to Render via `Procfile`

### Session 1 — Policy Engine & Test Agent

1. **Fixed dashboard circuit breaker display** — `/circuit-breaker/status` returns top-level `state`; frontend now reads `cbData.state` correctly instead of showing `"unknown"`.
2. **Created `policy_engine.py`** — deny-by-default tool-call evaluation:
   - **Blocked:** `DELETE`, `EXPORT`, `WRITE_EXTERNAL`, `QUERY_ALL`
   - **Allowed:** `READ`, `QUERY`, `STATUS`, `WRITE_INTERNAL`, `PING`
   - Returns `{allowed, reason, risk_level}`
3. **Hooked policy into `main.py`** — every `POST /pulse` and chat completions with an `operation` field runs through policy first
4. **Created `test_agent.py`** — sends 10 requests with BDI scores 0.1 → 0.9 and `entropy: 0.1` override to exercise BDI-driven governance without message entropy interference

### Session 2 — Dashboard & Kill Switch

1. **Dark professional dashboard UI** — slate/navy theme, status cards, colored breaker states
2. **`POST /circuit-breaker/open`** — manual kill switch to force OPEN state
3. **`POST /circuit-breaker/close`** — manual reset back to CLOSED
4. **TRIP KILL SWITCH button** — red button with confirmation alert on trip
5. **RESET BREAKER button** — green-outline button to restore CLOSED state
6. **Events table enhancements** — Status column (200/409/403/423), Decision badges, row color coding (green = allowed, red = blocked), summary counts

### Session 3 — Circuit Breaker Hardening

1. **Strict OPEN blocking** — when state is OPEN (or non-CLOSED), **all** requests are blocked; only explicit CLOSED allows traffic
2. **Removed half-open auto-recovery** — reset only via `POST /circuit-breaker/close` or dashboard
3. **Request drop semantics** — OPEN state returns empty **HTTP 503** with `Connection: close` and `X-Request-Dropped: 1` instead of 409, so agents do not treat responses as retry/conflict loops
4. **Per-agent cooldown** — when breaker is open, requests from the same `agent_id` are ignored for 30 seconds (`PULSE_AGENT_COOLDOWN_SECONDS`)
5. **Thread-safe** — `CircuitBreakerMiddleware` uses `threading.RLock` for concurrent agent requests
6. **Governance events** — all blocks/drops recorded in pulse feed with `decision`, `status_code`, `action`, `reason`

### Phase 1 — Infrastructure Hardening (Audit Trail)

**`audit.py` refactored with tamper-evident logging:**

- `Logger` class maintaining an internal linked hash chain
- `log_event(event_data)` — appends SHA-256 hash of previous event before hashing the new entry
- `verify_chain()` — validates each event's `previous_hash` matches its predecessor
- Uses only standard library (`hashlib`, `json`)
- Optional Supabase remote persistence when `SUPABASE_URL` / `SUPABASE_KEY` are set
- Integrated into chat completions audit path via `supabase_audit_client`

### Phase 2 — Synthesis Engine

**`synthesis_engine.py`:**

- `ForensicAuditor` class reads last 50 entries from the audit hash chain
- `generate_pattern_report()` — calculates blocked vs allowed frequency, flags agents responsible for >40% of failures
- `SynthesisEngineRunner` — background daemon thread (does not block proxy); started/stopped via FastAPI lifespan
- `GET /synthesis/report` — latest pattern report
- `POST /synthesis/run` — on-demand synthesis pass
- Standalone: `python synthesis_engine.py`

### Phase 3 — Compliance & Reporting

**`policy_engine.py` enhanced:**

- Blocked events tagged with regulatory frameworks: **EU AI Act**, **GDPR**, **SOC2**, **ISO 42001**
- Violation types mapped to framework tags (`blocked_delete`, `blocked_export`, etc.)
- `PolicyEvaluation` extended with `violation_type`, `regulatory_frameworks`, `operation`

**`compliance_report.py`:**

- `ComplianceEventStore` — thread-safe store of policy-blocked events
- `GET /compliance/export?format=json|markdown` — export compliance report
- `GET /compliance/events` — list recent blocked events
- Shadow mode support — policy violations logged but traffic allowed when `PULSE_SHADOW_MODE=true`

### Phase 4 — Stress Testing

**`red_agent.py`:**

- Rapid concurrent requests with escalating BDI scores
- Configurable via `PULSE_RED_AGENT_REQUESTS`, `PULSE_RED_AGENT_CONCURRENCY`, `PULSE_RED_AGENT_ID`
- Designed to run with shadow mode first to observe `would-block` without dropping traffic

---

## Current Architecture

```
Agents → POST /v1/chat/completions
           ├─ policy_engine (tool operations, regulatory tags)
           ├─ financial circuit breaker (>$5,000 blocked → 403)
           ├─ circuit_breaker.gate_request (BDI + entropy)
           │    ├─ CLOSED → proceed
           │    ├─ OPEN → drop (503 + Connection: close)
           │    └─ SHADOW_MODE → log would-block, allow through
           ├─ audit Logger (SHA-256 hash chain)
           └─ upstream LLM or baseline fallback

Background:
  synthesis_runner → ForensicAuditor → pattern reports

Events → pulse_feed → GET /events → frontend dashboard
Compliance → compliance_store → GET /compliance/export
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health + circuit breaker snapshot |
| `/events` | GET | Last 50 governance feed events |
| `/pulse` | GET | Event feed (configurable limit) |
| `/pulse` | POST | Tool-call with policy enforcement |
| `/pulse/bdi` | GET | BDI state snapshot |
| `/pulse/reset` | POST | Clear feed and BDI state |
| `/circuit-breaker/status` | GET | Breaker state, failure count |
| `/circuit-breaker/open` | POST | Manual kill switch → OPEN |
| `/circuit-breaker/close` | POST | Reset → CLOSED |
| `/v1/chat/completions` | POST | Agent proxy with full governance |
| `/synthesis/report` | GET | Latest forensic pattern report |
| `/synthesis/run` | POST | Trigger on-demand synthesis |
| `/compliance/export` | GET | Export compliance report (JSON or markdown) |
| `/compliance/events` | GET | List blocked compliance events |

---

## Key Files

| File | Purpose |
|------|---------|
| `main.py` | FastAPI app, routes, governance orchestration |
| `circuit_breaker.py` | Kill switch state machine, drop/cooldown logic |
| `policy_engine.py` | Deny-by-default tool policy + regulatory tags |
| `audit.py` | Tamper-evident SHA-256 hash chain logger |
| `synthesis_engine.py` | Forensic pattern analysis (background) |
| `compliance_report.py` | Compliance event store and export |
| `bdi.py` | BDI belief/desire/intention tracking |
| `pulse_feed.py` | In-memory governance event feed |
| `embeddings.py` | Text embeddings and novelty scoring |
| `baseline.py` | Fallback LLM responses |
| `refusal.py` | Refusal detection in outputs |
| `frontend/index.html` | Dark governance dashboard |
| `frontend/server.py` | Static file server (port 8080) |
| `test_agent.py` | 10-request BDI escalation test |
| `red_agent.py` | Concurrent stress test agent |
| `PROJECT_STATUS.md` | Quick resume guide (may be older) |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` / `PULSE_UPSTREAM_API_KEY` | — | Upstream LLM API key |
| `PULSE_UPSTREAM_CHAT_URL` | OpenAI URL | Upstream chat completions endpoint |
| `PULSE_UPSTREAM_TIMEOUT` | `120` | Upstream request timeout (seconds) |
| `PULSE_SHADOW_MODE` | `false` | Log would-block without dropping traffic |
| `PULSE_SYNTHESIS_ENABLED` | `true` | Enable background synthesis runner |
| `PULSE_SYNTHESIS_INTERVAL_SECONDS` | `60` | Synthesis polling interval |
| `PULSE_AGENT_COOLDOWN_SECONDS` | `30` | Per-agent cooldown when breaker is open |
| `PULSE_FEED_LIMIT` | `500` | Max events in pulse feed |
| `SUPABASE_URL` / `SUPABASE_KEY` | — | Optional remote audit persistence |
| `PULSE_BASE_URL` | `http://127.0.0.1:8000` | Target URL for test/red agents |

---

## How to Run Locally

### Terminal 1 — Backend
```powershell
cd C:\Users\Lenovo\pulse-proxy
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### Terminal 2 — Dashboard
```powershell
cd C:\Users\Lenovo\pulse-proxy\frontend
python server.py
```
Open http://localhost:8080

### Terminal 3 — Tests (optional)
```powershell
cd C:\Users\Lenovo\pulse-proxy
python test_agent.py          # BDI escalation test
python red_agent.py           # concurrent stress test

# Shadow mode (observe without blocking):
$env:PULSE_SHADOW_MODE="true"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
python red_agent.py
```

---

## Governance Thresholds

| Signal | Threshold | Effect |
|--------|-----------|--------|
| BDI score | > 0.65 | Trips circuit breaker |
| Shannon entropy | > 0.85 | Trips circuit breaker |
| Financial amount | > $5,000 | Blocked with HTTP 403 |
| Breaker OPEN | any | All requests dropped (503) |
| Blocked tool ops | DELETE, EXPORT, etc. | HTTP 403 (or shadow-allowed) |

Request body overrides for testing: `bdi_score`, `entropy`, `agent_id`, `operation`

---

## Uncommitted Changes

- `main.py` — `response_model=None` on `/compliance/export` to fix FastAPI response model conflict when returning markdown `PlainTextResponse`

---

## Suggested Next Steps

1. Commit and push to GitHub → Render auto-deploy
2. Wire Supabase credentials for remote audit persistence
3. Add authentication on kill-switch / reset endpoints for production
4. Tune BDI/entropy thresholds using shadow mode + red agent
5. Add half-open recovery logic when ready for gradual re-admission
