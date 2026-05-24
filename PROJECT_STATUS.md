# Pulse Governance Ledger — Project Status

## Last Updated: May 23, 2026

## Local Path
`C:\Users\Lenovo\pulse-proxy`

## GitHub
https://github.com/nazirwaqas163-svg/waqasnazir92 (push when ready)

## What Works ✅

### Backend (FastAPI, port 8000)
- `GET /health` — service health + circuit breaker snapshot
- `GET /events` — recent governance feed events
- `GET /circuit-breaker/status` — breaker state
- `POST /circuit-breaker/open` — manual kill switch (force OPEN)
- `POST /circuit-breaker/close` — reset to CLOSED
- `POST /v1/chat/completions` — agent proxy with BDI + entropy governance
- `POST /pulse` — tool-call endpoint with policy engine
- `policy_engine.py` — deny-by-default; blocks DELETE, EXPORT, WRITE_EXTERNAL, QUERY_ALL

### Circuit Breaker (`circuit_breaker.py`)
- **CLOSED only** allows requests through
- **OPEN** (or any non-CLOSED state) blocks **all** requests with **HTTP 409**
- High BDI (>0.65) or high entropy (>0.85) trips breaker to OPEN
- **No half-open auto-recovery** — reset only via `POST /circuit-breaker/close` or dashboard
- Optional overrides in request body: `bdi_score`, `entropy` (used by test agent)

### Frontend (`frontend/index.html`, port 8080)
- Dark governance dashboard
- Health + circuit breaker status cards
- **TRIP KILL SWITCH** → `POST /circuit-breaker/open` (confirmation alert)
- **RESET BREAKER** → `POST /circuit-breaker/close`
- Events table: Status (200/409), Decision badges, green/red row coloring
- Auto-polls Render when not on localhost; uses `http://127.0.0.1:8000` locally

### Test Agent (`test_agent.py`)
- Sends 10 requests with BDI 0.1→0.9; requests 8–10 blocked (409) when threshold exceeded
- Set `PULSE_BASE_URL` for remote testing

### Deployed (Render)
https://pulse-proxy-je0p.onrender.com — push to GitHub to update

---

## How to Resume

### 1. Open project
```
C:\Users\Lenovo\pulse-proxy
```

### 2. Start backend (terminal 1)
```powershell
cd C:\Users\Lenovo\pulse-proxy
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### 3. Start frontend (terminal 2)
```powershell
cd C:\Users\Lenovo\pulse-proxy\frontend
python server.py
```

### 4. Open dashboard
http://localhost:8080

### 5. Optional — run test agent (terminal 3)
```powershell
cd C:\Users\Lenovo\pulse-proxy
python test_agent.py
```

### Dependencies (if fresh machine)
```powershell
cd C:\Users\Lenovo\pulse-proxy
python -m pip install -r requirements.txt
```

---

## Key Files

| File | Purpose |
|------|---------|
| `main.py` | FastAPI app, routes, governance hooks |
| `circuit_breaker.py` | Kill switch state machine |
| `policy_engine.py` | Tool-call allow/deny policy |
| `bdi.py` | BDI state tracking |
| `pulse_feed.py` | In-memory event feed |
| `frontend/index.html` | Dashboard UI |
| `frontend/server.py` | Static file server :8080 |
| `test_agent.py` | Simulated agent load test |

---

## API Quick Reference

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/health` | GET | OK + breaker state |
| `/events` | GET | Last 50 events |
| `/circuit-breaker/status` | GET | `state`, `allows_requests` |
| `/circuit-breaker/open` | POST | Manual trip → OPEN |
| `/circuit-breaker/close` | POST | Reset → CLOSED |
| `/v1/chat/completions` | POST | Agent requests; 409 when blocked |
| `/pulse` | POST | Tool calls; body: `{ "operation": "READ" }` |

---

## Completed (this session)
- [x] Circuit breaker state in frontend
- [x] Policy engine + POST /pulse
- [x] test_agent.py
- [x] Dark dashboard + kill switch + reset buttons
- [x] Blocked/allowed event coloring (200 green, 409 red)
- [x] OPEN blocks all traffic with 409 until manual close

## Phase 2 — Synthesis Engine ✅
- `synthesis_engine.py` — `ForensicAuditor` (last 50 audit entries), `generate_pattern_report()`
- Background daemon thread via `SynthesisEngineRunner` (does not block proxy)
- `GET /synthesis/report` | `POST /synthesis/run`
- Standalone: `python synthesis_engine.py`

## Phase 3 — Compliance & Reporting ✅
- `policy_engine.py` — blocked events tagged with **EU AI Act**, **GDPR**, **SOC2**, **ISO 42001**
- `compliance_report.py` — `ComplianceEventStore`, export JSON/markdown
- `GET /compliance/export?format=json|markdown` | `GET /compliance/events`

## Phase 4 — Stress Testing ✅
- `red_agent.py` — rapid concurrent BDI escalation probes
- **Shadow mode:** `PULSE_SHADOW_MODE=true` — evaluates governance, logs `would-block`, does **not** drop traffic or trip breaker

```powershell
$env:PULSE_SHADOW_MODE="true"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
python red_agent.py
```

## Suggested Next Steps
1. Push to GitHub → Render auto-deploy
2. Wire Supabase audit (`audit.py`) if credentials available
3. Add auth on kill-switch / reset endpoints for production
4. Tune BDI/entropy thresholds using shadow mode + red agent

## Architecture
```
Agents → POST /v1/chat/completions
           ├─ policy_engine (tool operations)
           ├─ circuit_breaker (BDI + entropy, OPEN = 409)
           └─ upstream LLM or baseline fallback
Events → pulse_feed → GET /events → frontend dashboard
```
