# Pulse SDK

**AI Agent Governance Middleware — ASEAN-Native**

The Pulse SDK lets you add governance to any AI agent in under 10 lines of Python. Every agent request is intercepted, scored, and enforced against PDPA Malaysia, Singapore Model AI Governance Framework, and Vietnam AI Law before it reaches your LLM.

> "LangSmith/Helicone tell you what went wrong. Pulse stops it before it executes."

---

## Installation

```bash
pip install httpx
```

Copy `pulse_sdk.py` into your project, or install directly from the repo:

```bash
pip install git+https://github.com/nazirwaqas163-svg/waqasnazir92.git#subdirectory=pulse-sdk
```

---

## Quickstart

```python
from pulse_sdk import PulseGuard

guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="my-agent-001"
)

guard.new_session()

result = guard.intercept(
    input_text="Summarise Q3 sales data for the board",
    output_text="Q3 revenue was RM 4.2M across 3 regions..."
)

print(result)  # returns output_text if allowed
```

That's it. If the request violates a governance rule, Pulse raises `PulseCircuitTrippedException` before the output reaches your application.

---

## Core Concepts

### Sessions

Each conversation or workflow run should have its own session. Pulse tracks behavioural drift, entropy, and escalation patterns across turns within a session.

```python
session_id = guard.new_session()  # generates a UUID
```

Call `new_session()` at the start of each agent run. Reuse the same guard instance across turns.

### Intercept

`intercept()` is the main governance hook. Call it after your agent produces output, before you act on it.

```python
output = guard.intercept(
    input_text=user_message,
    output_text=agent_response,
    metadata={"step": 3, "workflow": "procurement"}
)
```

**What Pulse scores on every call:**

| Signal | What it measures |
|---|---|
| BDI Score | Behavioural Drift Index — escalating risk across session turns |
| Shannon Entropy | Randomness of the current message |
| Exfiltration Risk | Data export / external endpoint patterns |
| Shadow Score | Unregistered agent, unauthorized spawn, scope violation |
| Swarm Detection | Multiple concurrent sessions from the same agent |
| Org Policy | Custom keyword rules set by your organisation |

**What happens on a breach:**

1. Legal hold auto-opened with SHA-256 chain hash
2. Signed HMAC-SHA256 webhook fired to your registered receiver
3. Offending agent auto-isolated (returns 423 on all future calls)
4. Sealed incident PDF generated with ASEAN regulatory mapping

### Fail-Open Mode

By default `fail_open=False` — if the Pulse backend is unreachable or returns an unexpected HTTP error, the SDK raises. Set `fail_open=True` only when your risk policy explicitly permits ungoverned pass-through.

```python
guard = PulseGuard(base_url="...", agent_id="...", fail_open=False)
```

---

## API Reference

### `PulseGuard`

```python
PulseGuard(base_url: str, agent_id: str, fail_open: bool = False, api_key: str | None = None)
```

| Parameter | Type | Description |
|---|---|---|
| `base_url` | `str` | Pulse backend URL |
| `agent_id` | `str` | Unique identifier for this agent |
| `fail_open` | `bool` | Pass through on backend/network errors (default: False) |
| `api_key` | `str | None` | Organization API key sent as `X-API-Key` |

---

### `guard.new_session()`

Starts a new governance session. Returns the generated `session_id`.

```python
session_id = guard.new_session()
```

### `guard.ingest_trace_spans(spans)`

Send up to 100 OpenTelemetry-style spans to the tenant-scoped `/v1/traces` endpoint. Apply `migrations/0002_agent_traces.sql` to Supabase before use. The organization API key must be configured on the guard.

```python
guard.ingest_trace_spans([{
    "trace_id": "0123456789abcdef0123456789abcdef",
    "span_id": "0123456789abcdef",
    "name": "agent.invoke",
    "started_at": "2026-11-18T10:00:00Z",
    "ended_at": "2026-11-18T10:00:01Z",
    "status": "ok",
    "attributes": {"gen_ai.operation.name": "chat"},
}])
```

---

### `guard.intercept(input_text, output_text, metadata=None)`

Sends input/output to Pulse for governance review.

- Returns `output_text` unchanged if allowed
- Raises `PulseCircuitTrippedException` if blocked

```python
output = guard.intercept(
    input_text="user message",
    output_text="agent response",
    metadata={"step": 1}
)
```

---

### `guard.intercept_raw(input_text, output_text, metadata=None)`

Like `intercept()` but returns a `PulseResult` object instead of a plain string. Use this when you want to inspect threat level or policy violations before deciding what to do.

```python
result = guard.intercept_raw(input_text, output_text)

if result.threat_level == "CRITICAL" or result.policy_violations:
    raise GovernanceException(result)
```

---

### `@guard.watch()`

Decorator that automatically intercepts the input/output of any function.

```python
@guard.watch()
def summarise_contract(text: str) -> str:
    return llm.complete(f"Summarise: {text}")
```

Pulse intercepts the function's arguments as `input_text` and its return value as `output_text` after every call.

---

### `PulseResult`

Returned by `intercept_raw()`. Exposes governance signals as Python attributes.

```python
result = guard.intercept_raw(input_text, output_text)

result.threat_level       # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
result.fired_threats      # ["exfiltration", "policy_violation", ...]
result.policy_violations  # list of org policy violations
result.allowed            # True if request passed
result.blocked            # True if circuit breaker tripped
```

---

### `GovernanceException`

Raise this when a `PulseResult` indicates a breach. Carries the full result for upstream handling.

```python
from pulse_sdk import PulseGuard, PulseResult, GovernanceException

result = guard.intercept_raw(input_text, output_text)
if result.threat_level in ("HIGH", "CRITICAL") or result.policy_violations:
    raise GovernanceException(result)
```

---

### `PulseCircuitTrippedException`

Raised automatically by `intercept()` and `intercept_raw()` when Pulse blocks the request.

```python
try:
    output = guard.intercept(input_text, output_text)
except PulseCircuitTrippedException as e:
    print(e.status_code)  # 409 | 423 | 503
    print(e.detail)       # full Pulse response detail
```

---

## ASEAN Use Case Examples

### Example 1 — Malaysian Bank: Customer Data Protection

```python
from pulse_sdk import PulseGuard, GovernanceException

guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="loan-screening-agent",
    fail_open=False  # hard block if governance is down
)

guard.new_session()

def process_loan_application(customer_data: dict) -> str:
    prompt = f"Assess loan eligibility for: {customer_data}"
    response = llm.complete(prompt)

    result = guard.intercept_raw(
        input_text=prompt,
        output_text=response,
        metadata={"workflow": "loan_screening", "jurisdiction": "MY"}
    )

    if result.policy_violations:
        # PDPA Malaysia — customer data in output flagged
        raise GovernanceException(result)

    return response
```

**What Pulse checks:** org policy for PII in output, exfiltration risk if customer data appears in an external-endpoint pattern, PDPA Malaysia 24hr breach notification if triggered.

---

### Example 2 — Singapore Fintech: Procurement Agent

```python
guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="procurement-agent-sg"
)

guard.new_session()

@guard.watch(metadata={"workflow": "procurement", "jurisdiction": "SG"})
def request_vendor_quote(vendor_id: str, amount: float) -> str:
    # Pulse auto-intercepts after this function returns
    return erp_api.request_quote(vendor_id, amount)
```

**What Pulse checks:** financial transaction guard (blocks >$5,000 by default), BDI escalation if the agent repeatedly overrides approval steps, Singapore MGF clause 2.2 if fully automated decisions on individuals are detected.

---

### Example 3 — Vietnam Insurance: Multi-Turn Claims Agent

```python
guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="claims-agent-vn"
)

guard.new_session()

for turn in conversation_turns:
    try:
        output = guard.intercept(
            input_text=turn["user"],
            output_text=turn["agent"],
            metadata={"turn": turn["number"], "jurisdiction": "VN"}
        )
    except PulseCircuitTrippedException as e:
        # Vietnam AI Law — agent isolated, incident report auto-generated
        notify_compliance_officer(e.detail)
        break
```

**What Pulse checks:** session-level BDI drift across turns, Shannon entropy spike detection, swarm detection if multiple claim sessions open simultaneously, Vietnam AI Law 72hr reporting obligation if breach confirmed.

---

## Advanced Usage

### Registering an Agent

Register your agent with Pulse to unlock full passport and breach-readiness scoring:

```python
import httpx

httpx.post("https://pulse-proxy-8dqx.onrender.com/agents/register", json={
    "agent_id": "loan-screening-agent",
    "name": "Loan Screening Agent",
    "owner": "credit-risk-team",
    "scope": ["read:customer_data", "write:loan_decision"],
    "description": "Screens loan applications against credit policy"
})
```

Unregistered agents score 1.0 on the Shadow Score's unregistered component — register early.

### Setting Org Policies

Define custom keyword rules enforced on every `/intercept` call for your org:

```python
httpx.post("https://pulse-proxy-8dqx.onrender.com/org/policies", json={
    "org_id": "your-org-id",
    "policy_id": "no-pii-in-output",
    "name": "No PII in agent output",
    "rules": [
        {"match": "customer_id", "action": "block", "severity": "HIGH"},
        {"match": "ic_number", "action": "block", "severity": "CRITICAL"},
        {"match": "phone", "action": "alert", "severity": "MEDIUM"}
    ]
})
```

### Checking Agent Passport

Download the Pulse Passport (PP-1) for any agent — a signed compliance document with full session history, breach readiness verdict, and ASEAN regulatory obligations:

```python
# JSON
httpx.get("https://pulse-proxy-8dqx.onrender.com/agents/loan-screening-agent/passport")

# PDF
httpx.get("https://pulse-proxy-8dqx.onrender.com/agents/loan-screening-agent/passport?format=pdf")
```

---

## Error Handling Reference

| Exception | When | Status Code |
|---|---|---|
| `PulseCircuitTrippedException` | Circuit breaker tripped | 409 |
| `PulseCircuitTrippedException` | Agent isolated | 423 |
| `PulseCircuitTrippedException` | Backend dropped request | 503 |
| `GovernanceException` | Manual raise on HIGH/CRITICAL result | — |
| `httpx.HTTPError` | Network error, `fail_open=False` | — |

---

## Dashboard

View all governance events, compliance exposure, and agent topology at:

**`https://pulse-dashboard-cx7x.onrender.com`**

New organisation? Sign up at:

**`https://pulse-dashboard-cx7x.onrender.com/signup.html`**

Paste your API key into Settings to scope the dashboard to your organisation's events only.

---

## Compliance Coverage

| Framework | Jurisdiction | Obligation | Pulse Response |
|---|---|---|---|
| PDPA Malaysia (Amended 2024) | MY | Notify PDPC within 24hr of breach | Auto legal hold + DPO email |
| Singapore Model AI Governance | SG | Incident review within 72hr | Evidence package + audit viewer link |
| Vietnam AI Law (Art. 9) | VN | Report to authority within 72hr | Sealed PDF + RFC 3161 timestamp |
| ISO/IEC 42001 | INTL | Log and retain AI incident records | SHA-256 immutable audit ledger |

---

## Backend Endpoints Used by the SDK

| Endpoint | Method | Purpose |
|---|---|---|
| `/intercept` | POST | Main governance hook |
| `/health` | GET | Backend health check |
| `/agents/register` | POST | Register agent identity |
| `/agents/{id}/passport` | GET | Download Pulse Passport PP-1 |
| `/org/policies` | POST/GET | Manage org custom policies |
| `/legal-hold` | GET | List active legal holds |

Full API reference: `https://pulse-proxy-8dqx.onrender.com/docs`

---

## Built By

Waqas Nazir — non-technical founder, ASEAN AI governance specialist.
All implementation by Claude (Anthropic).

Pulse is ASEAN-native by design. Not a universal compliance tool — a precision instrument for PDPA Malaysia, Singapore MGF, and Vietnam AI Law.

