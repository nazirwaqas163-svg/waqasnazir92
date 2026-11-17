# Pulse SDK — Developer Documentation

**Version:** 1.0  
**Package:** `pulse_sdk.py`  
**Backend:** `https://pulse-proxy-8dqx.onrender.com`

---

## Overview

The Pulse SDK lets you add ASEAN-compliant AI agent governance to any Python application in under 10 lines. It intercepts every agent action, scores it for risk, enforces org policies, and raises `GovernanceException` if a breach is detected — before the action executes.

```python
from pulse_sdk import PulseGuard

guard = PulseGuard(agent_id="my-agent", pulse_url="https://pulse-proxy-8dqx.onrender.com")
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

If the variable is not configured, privileged routes return HTTP 503. Agent interception, service health, and the public event feed remain available.

---

## Quick Start

```python
from pulse_sdk import PulseGuard, PulseResult, GovernanceException

# 1. Initialise once per agent
guard = PulseGuard(
    agent_id="invoice-processing-agent",
    pulse_url="https://pulse-proxy-8dqx.onrender.com",
    session_id="session-abc-001",      # optional — auto-generated if omitted
    org_id="acme-corp",                # optional — used for org policy enforcement
)

# 2. Call intercept() after every agent turn
try:
    result = guard.intercept(
        input_text=user_message,
        output_text=agent_response,
    )
    print(f"Threat level: {result.threat_level}")   # LOW / MEDIUM / HIGH / CRITICAL
    print(f"Allowed: {result.allowed}")              # True

except GovernanceException as e:
    print(f"Blocked: {e.reason}")
    print(f"Hold ID: {e.hold_id}")                  # legal hold auto-opened
    # Do not execute the agent action
```

---

## Classes

### `PulseGuard`

Main entry point. One instance per agent.

```python
PulseGuard(
    agent_id: str,
    pulse_url: str = "https://pulse-proxy-8dqx.onrender.com",
    session_id: str | None = None,        # auto-generated if None
    parent_session_id: str | None = None, # for multi-agent lineage tracking
    org_id: str = "demo-org",
    timeout: float = 30.0,
)
```

**Methods:**

#### `intercept(input_text, output_text, metadata=None) → PulseResult`

Sends the agent turn to Pulse for governance scoring. Raises `GovernanceException` if the circuit breaker trips or the agent is isolated.

```python
result = guard.intercept(
    input_text="Retrieve customer records for KL branch",
    output_text="Retrieved 847 records including name, IC, phone",
    metadata={"operation": "data_retrieval", "org_id": "acme-corp"},
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `input_text` | `str` | The agent's input / prompt |
| `output_text` | `str` | The agent's output / response |
| `metadata` | `dict \| None` | Optional extra context (operation name, org_id override) |

#### `intercept_raw(input_text, output_text, metadata=None) → PulseResult`

Same as `intercept()` but never raises — returns a `PulseResult` with `allowed=False` instead of raising `GovernanceException`. Use when you want to handle the block decision yourself.

```python
result = guard.intercept_raw(input_text=..., output_text=...)
if not result.allowed:
    log_blocked_action(result)
    return
```

#### `register() → dict`

Register the agent in the Pulse registry. Call once at startup for full governance coverage (unregistered agents carry a higher shadow score).

```python
guard.register(
    name="Invoice Processing Agent",
    owner="finance-team@acme.com",
    scope=["read:invoices", "write:payments"],
    description="Processes vendor invoices and triggers payment workflows",
)
```

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

### `GovernanceException`

Raised by `intercept()` when Pulse blocks the agent action.

```python
GovernanceException(
    reason: str,        # human-readable block reason
    hold_id: str | None # legal hold ID if auto-opened
    status_code: int    # HTTP status from /intercept (409 = tripped, 423 = isolated)
    raw: dict           # full raw error response
)
```

**Example:**

```python
try:
    result = guard.intercept(input_text=..., output_text=...)
except GovernanceException as e:
    if e.status_code == 423:
        print(f"Agent is isolated — contact compliance: {e.reason}")
    elif e.status_code == 409:
        print(f"Circuit breaker tripped: {e.reason}")
        print(f"Evidence hold: {e.hold_id}")
```

---

## ASEAN Use Case Examples

### Malaysia — PDPA Customer Data Handler

```python
from pulse_sdk import PulseGuard, GovernanceException

guard = PulseGuard(
    agent_id="customer-data-agent-my",
    org_id="maybank-digital",
    pulse_url="https://pulse-proxy-8dqx.onrender.com",
)

# Register agent with scopes (recommended)
guard.register(
    name="Customer Data Handler",
    owner="dpo@maybank.com",
    scope=["read:customer_pii", "read:account_data"],
    description="Retrieves customer records for KYC compliance",
)

def handle_customer_query(user_input: str, agent_output: str) -> str:
    try:
        result = guard.intercept(
            input_text=user_input,
            output_text=agent_output,
            metadata={"operation": "kyc_lookup", "jurisdiction": "MY"},
        )
        return agent_output  # safe to return

    except GovernanceException as e:
        # PDPA Malaysia — log breach attempt, notify DPO within 24 hours
        send_pdpa_alert(dpo_email="dpo@maybank.com", reason=e.reason, hold_id=e.hold_id)
        return "Request blocked by data governance policy."
```

---

### Singapore — Model AI Governance Framework

```python
from pulse_sdk import PulseGuard, GovernanceException

guard = PulseGuard(
    agent_id="procurement-agent-sg",
    org_id="dbs-procurement",
    pulse_url="https://pulse-proxy-8dqx.onrender.com",
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

    except GovernanceException as e:
        # Auto-incident report + RFC 3161 timestamped hold already created
        notify_compliance(hold_id=e.hold_id, jurisdiction="SG")
        raise
```

---

### Vietnam — AI Law Article 9 Incident Reporting

```python
from pulse_sdk import PulseGuard, GovernanceException

guard = PulseGuard(
    agent_id="logistics-agent-vn",
    org_id="vinfast-logistics",
    pulse_url="https://pulse-proxy-8dqx.onrender.com",
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
from pulse_sdk import PulseGuard

# Parent orchestrator
orchestrator = PulseGuard(agent_id="orchestrator", session_id="sess-orch-001")

# Child agents reference the parent session
child_a = PulseGuard(
    agent_id="data-agent-a",
    parent_session_id="sess-orch-001",   # links lineage in Pulse
)
child_b = PulseGuard(
    agent_id="data-agent-b",
    parent_session_id="sess-orch-001",
)

# Each child call is governed independently, lineage tracked
child_a.intercept(input_text="...", output_text="...")
child_b.intercept(input_text="...", output_text="...")
```

---

## Error Handling Reference

| Status Code | Exception | Meaning |
|-------------|-----------|---------|
| 409 | `GovernanceException` | Circuit breaker tripped — agent behaviour exceeded risk threshold |
| 423 | `GovernanceException` | Agent is isolated — quarantined due to prior breach |
| 503 | `GovernanceException` | Pulse engine dropped the request — circuit breaker open |
| 5xx | `GovernanceException` | Backend error — fail-open or fail-closed per your policy |

**Fail-open pattern** (allow action if Pulse is unreachable — not recommended for high-stakes):
```python
try:
    guard.intercept(input_text=..., output_text=...)
except GovernanceException:
    raise  # always block on governance failure
except Exception:
    pass   # Pulse unreachable — allow (fail-open)
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
