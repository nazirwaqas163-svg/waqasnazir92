# Pulse SDK — Developer Documentation

**Version:** 1.0  
**Package:** `pulse_sdk.py`  
**Backend:** `https://pulse-proxy-8dqx.onrender.com`

---

## Overview

The Pulse SDK sends agent input and output to the Pulse service for monitoring. The `watch` decorator reports the result after the wrapped function runs, so it is for monitoring and logging; use a separate pre-execution policy gate when an action must be stopped before it runs.

```python
import os
from pulse_sdk import PulseGuard

# Store an organization API key in your agent environment.
guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="my-agent",
    api_key=os.getenv("PULSE_ORG_API_KEY"),
    fail_open=False,
)
result = guard.intercept(input_text="...", output_text="...")
```

---

## Installation

```bash
pip install httpx  # only external dependency
```

Copy `pulse_sdk.py` into your project root, or add it to your package.

---

## Admin API access

Privileged control-plane routes require the backend environment variable `PULSE_ADMIN_API_KEY`. Set it to a long random secret in the hosting environment, then enter the same key in the dashboard's **Admin API Key** setting. The dashboard keeps it in the current browser tab and sends it only as `X-Admin-API-Key`.

If the variable is not configured, privileged routes return HTTP 503. Service health remains public; operational dashboard data requires an admin key, and agent interception requires a valid organization API key. New organization keys are stored as SHA-256 digests; keys issued before that change continue to work until rotated.

For named dashboard access, configure `PULSE_ADMIN_KEYS_JSON` as a JSON array of key records, for example `[{"user_id":"alice","role":"admin","key":"<long-random-secret>"},{"user_id":"bob","role":"viewer","key":"<different-long-random-secret>"}]`. Roles are `viewer`, `operator`, and `admin`. Remove the legacy `PULSE_ADMIN_API_KEY` after replacing it; while it remains configured it continues to grant administrator access.

Anonymous demo interception is disabled by default. Set `PULSE_ALLOW_ANONYMOUS_DEMO=true` only for an isolated demo environment.

Agent isolation requests include an explicit `org_id`; isolation and release are scoped to that organization, so matching agent IDs in other tenants remain unaffected.

For restart- and worker-safe quarantine, apply `migrations/0003_durable_agent_isolations.sql`, then set `PULSE_DURABLE_ISOLATION_ENABLED=true` on the API service and redeploy. When enabled, failure to read or write the isolation table returns HTTP 503 rather than allowing requests through. With the flag off, isolation uses process memory and `/health` reports degraded readiness.

To persist BDI history and per-session baseline counts across restarts and workers, apply `migrations/0004_durable_agent_sessions.sql`, set `PULSE_DURABLE_SESSION_STATE_ENABLED=true`, and redeploy. Session writes use a versioned database function with optimistic retries; when the durable path is enabled, storage errors return HTTP 503. `/health` reports degraded readiness while durable session state is disabled.

## Trace ingestion

The tenant API accepts OpenTelemetry-style spans at `POST /v1/traces` and returns recent spans from `GET /v1/traces` or one trace by ID from `GET /v1/traces/{trace_id}`. Send the organization API key in `X-API-Key`. Apply `migrations/0002_agent_traces.sql` to Supabase before use. Batches are limited to 100 spans and 2 MB; each JSON attribute/resource/event field is limited to 64 KB. The service stores telemetry as submitted, so instrumentations should avoid sending secrets or unneeded personal data.

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

## Quick Start

```python
import os
from pulse_sdk import PulseGuard, PulseCircuitTrippedException

# 1. Initialise once per agent
guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="invoice-processing-agent",
    api_key=os.environ["PULSE_ORG_API_KEY"],
    fail_open=False,
)
session_id = guard.new_session()  # optional — creates a session for this run

# 2. Call intercept() after every agent turn
try:
    result = guard.intercept_raw(
        input_text=user_message,
        output_text=agent_response,
    )
    print(f"Threat level: {result.threat_level}")   # LOW / MEDIUM / HIGH / CRITICAL
    print(f"Allowed: {result.allowed}")              # True

except PulseCircuitTrippedException as e:
    print(f"Blocked ({e.status_code}): {e}")
    # Do not execute the agent action
```

---

## Classes

### `PulseGuard`

Main entry point. One instance per agent.

```python
PulseGuard(
    agent_id: str,
    base_url: str,
    agent_id: str,
    fail_open: bool = False,
    api_key: str | None = None,
)
```

**Methods:**

#### `intercept(input_text, output_text, metadata=None) → PulseResult`

Sends the agent turn to Pulse for governance scoring. Raises `PulseCircuitTrippedException` if the circuit breaker trips or the agent is isolated.

```python
result = guard.intercept(
    input_text="Retrieve customer records for KL branch",
    output_text="Retrieved 847 records including name, IC, phone",
    metadata={"operation": "data_retrieval"},
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `input_text` | `str` | The agent's input / prompt |
| `output_text` | `str` | The agent's output / response |
| `metadata` | `dict \| None` | Optional event context. Tenant scope comes from the verified `X-API-Key` header. |

#### `intercept_raw(input_text, output_text, metadata=None) → PulseResult`

Same as `intercept()` but never raises — returns a `PulseResult` with `allowed=False` instead of raising `PulseCircuitTrippedException`. Use when you want to handle the block decision yourself.

```python
result = guard.intercept_raw(input_text=..., output_text=...)
if not result.allowed:
    log_blocked_action(result)
    return
```

Agent registration is currently an administrator operation through the control-plane API; the Python SDK does not expose a `register()` method.

---

### `PulseResult`

Returned by `intercept()` and `intercept_raw()`.

```python
result.allowed             # bool   — True if action is permitted
result.threat_level        # str    — "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
result.fired_threats       # list   — threat classes that fired (e.g. ["exfiltration"])
result.policy_violations   # list   — org policy rules that matched
result.bdi_score           # float  — 0.0–1.0 behavioural divergence index
result.entropy             # float  — 0.0–1.0 Shannon entropy of input
result.drift_status        # str    — "stable" | "elevated" | "critical"
result.legal_holds         # list   — hold IDs opened this turn (if any)
result.request_id          # str    — UUID for this intercept call
result.session_id          # str    — session this turn belongs to
result.raw                 # dict   — full raw response from /intercept
```

**Example:**

```python
result = guard.intercept(input_text=..., output_text=...)

if result.threat_level in ("HIGH", "CRITICAL"):
    notify_compliance_officer(result.request_id)

if result.policy_violations:
    for v in result.policy_violations:
        print(f"Policy violated: {v['policy_name']} — {v['reason']}")

if result.legal_holds:
    print(f"Legal hold opened: {result.legal_holds[0]}")
```

---

### `PulseCircuitTrippedException`

Raised by `intercept()` when Pulse blocks the action with HTTP 409, 423, or 503. Other HTTP errors raise `httpx.HTTPStatusError` when `fail_open=False` (the default).

```python
PulseCircuitTrippedException(message, status_code, detail)
```

**Example:**

```python
try:
    result = guard.intercept(input_text=..., output_text=...)
except PulseCircuitTrippedException as e:
    print(f"Pulse blocked the action ({e.status_code}): {e}")
```

---

## ASEAN Use Case Examples

### Malaysia — PDPA Customer Data Handler

```python
import os
from pulse_sdk import PulseGuard, PulseCircuitTrippedException

guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="customer-data-agent-my",
    api_key=os.environ["PULSE_ORG_API_KEY"],
)

# Register agent with scopes (recommended)
# Register this agent through the administrator control-plane API before use.

def handle_customer_query(user_input: str, agent_output: str) -> str:
    try:
        result = guard.intercept(
            input_text=user_input,
            output_text=agent_output,
            metadata={"operation": "kyc_lookup", "jurisdiction": "MY"},
        )
        return agent_output  # safe to return

    except PulseCircuitTrippedException as e:
        # PDPA Malaysia — log breach attempt, notify DPO within 24 hours
        send_pdpa_alert(dpo_email="dpo@maybank.com", reason=str(e), hold_id=None)
        return "Request blocked by data governance policy."
```

---

### Singapore — Model AI Governance Framework

```python
import os
from pulse_sdk import PulseGuard, PulseCircuitTrippedException

guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="procurement-agent-sg",
    api_key=os.environ["PULSE_ORG_API_KEY"],
)

def run_procurement_action(prompt: str, response: str):
    try:
        result = guard.intercept(input_text=prompt, output_text=response)

        # Singapore MGF — log all AI decisions on individuals
        if result.threat_level != "LOW":
            log_mgf_decision(
                agent_id=guard.agent_id,
                threat_level=result.threat_level,
                bdi_score=result.bdi_score,
                request_id=result.request_id,
            )

        return response

    except PulseCircuitTrippedException as e:
        # Auto-incident report + RFC 3161 timestamped hold already created
        notify_compliance(hold_id=e.hold_id, jurisdiction="SG")
        raise
```

---

### Vietnam — AI Law Article 9 Incident Reporting

```python
import os
from pulse_sdk import PulseGuard, PulseCircuitTrippedException

guard = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="logistics-agent-vn",
    api_key=os.environ["PULSE_ORG_API_KEY"],
)

def process_logistics_action(input_text: str, output_text: str):
    result = guard.intercept_raw(input_text=input_text, output_text=output_text)

    if not result.allowed:
        # Vietnam AI Law — report to competent authority within 72 hours
        # Evidence package with RFC 3161 timestamp already sealed in Pulse
        file_vietnam_ai_incident_report(
            hold_ids=result.legal_holds,
            agent_id=guard.agent_id,
            session_id=result.session_id,
        )
        return None

    return output_text
```

---

### Multi-Agent Swarm (Parent-Child Session Lineage)

```python
import os
from pulse_sdk import PulseGuard

# Parent orchestrator
orchestrator = PulseGuard(base_url="https://pulse-proxy-8dqx.onrender.com", agent_id="orchestrator", api_key=os.environ["PULSE_ORG_API_KEY"])
orchestrator.new_session()

# Child agents reference the parent session
child_a = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="data-agent-a",
    api_key=os.environ["PULSE_ORG_API_KEY"],
)
child_b = PulseGuard(
    base_url="https://pulse-proxy-8dqx.onrender.com",
    agent_id="data-agent-b",
    api_key=os.environ["PULSE_ORG_API_KEY"],
)

# Each child call is governed independently, lineage tracked
child_a.intercept(input_text="...", output_text="...")
child_b.intercept(input_text="...", output_text="...")
```

---

## Error Handling Reference

| Status Code | Exception | Meaning |
|-------------|-----------|---------|
| 409 | `PulseCircuitTrippedException` | Circuit breaker tripped — agent behaviour exceeded risk threshold |
| 423 | `PulseCircuitTrippedException` | Agent is isolated — quarantined due to prior breach |
| 503 | `PulseCircuitTrippedException` | Pulse engine dropped the request — circuit breaker open |
| Other 4xx/5xx | `httpx.HTTPStatusError` | Unexpected service or authorization error; raised by default |

**Fail-open** (allow action if Pulse is unavailable):
```python
guard = PulseGuard(base_url="...", agent_id="...", api_key="...", fail_open=True)
guard.intercept(input_text="...", output_text="...")
```

**Fail-closed pattern** (block if Pulse is unreachable — recommended for regulated environments):
```python
try:
    guard.intercept(input_text=..., output_text=...)
except Exception:
    raise  # block on any failure
```

---

## Key Concepts

**Baseline period:** The first 5 turns of a session establish a behavioural baseline. Exfiltration alerts and drift detection only fire after baselining is complete — this prevents false positives on new sessions.

**BDI Score:** Belief-Desire-Intention score (0.0–1.0). Measures how much an agent's internal state has diverged from expected behaviour. Above 0.85 is HIGH risk territory.

**Shannon Entropy:** Measures information density of the agent's input (0.0–1.0). High entropy on repeated identical inputs suggests anomalous behaviour.

**Legal Hold + RFC 3161:** When a breach is detected, Pulse automatically opens a legal hold, seals it with a SHA-256 hash, and requests an RFC 3161 timestamp from an external Certificate Authority. The resulting token is independently verifiable — relevant for PDPA Malaysia Section 30, Singapore PDPC, and Vietnam AI Law Article 9.

**Org Policies:** Custom keyword-based rules per organisation, stored in Supabase and enforced on every `/intercept` call. Create via `POST /org/policies`.

---

## Jurisdiction Quick Reference

| Country | Regulation | Breach Window | Pulse Coverage |
|---------|-----------|---------------|----------------|
| Malaysia | PDPA 2010 (Amended 2024) | 72hr (rec. 24hr) | ✅ Auto legal hold + RFC 3161 |
| Singapore | PDPA + Model AI Governance Framework | 72hr | ✅ Auto legal hold + RFC 3161 |
| Vietnam | AI Law 2024 (Art. 9) | 72hr | ✅ Auto legal hold + RFC 3161 |

---

*Pulse AI Governance Middleware — ASEAN-native, vendor-neutral, intercepts before execution.*

## Durable circuit-breaker state

To share the kill-switch state across API instances, apply `migrations/0005_durable_circuit_breaker.sql` to Supabase and set `PULSE_DURABLE_CIRCUIT_BREAKER_ENABLED=true` on the API service. Gated requests then read the shared state before evaluation; database errors return HTTP 503. Until the migration and flag are active, breaker state is process-local and health reports degraded readiness.
