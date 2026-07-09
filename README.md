# Pulse SDK

**AI Agent Governance Middleware for ASEAN**

Pulse sits between your AI agent and its output. Every call is intercepted, scored for behavioral drift, checked against org policies, and mapped to ASEAN regulatory obligations — in real time, before the response reaches your system.

Built by [Waqas Nazir](https://github.com/nazirwaqas163-svg) · Backend: [pulse-proxy-8dqx.onrender.com](https://pulse-proxy-8dqx.onrender.com)

---

## Install

````bash
pip install httpx
````

Copy `pulse_sdk.py` into your project. PyPI publishing coming soon.

---

## Quickstart — 3 lines

````python
from pulse_sdk import PulseGuard

guard = PulseGuard("https://pulse-proxy-8dqx.onrender.com", agent_id="my-agent")
guard.new_session()

# Wrap any agent call
result = guard.intercept(input_text, output_text)
````

---

## Stage 4 — Governance Enforcement Pattern

Use `intercept_raw()` when you need to act on what Pulse found:

````python
from pulse_sdk import PulseGuard, GovernanceException

guard = PulseGuard("https://pulse-proxy-8dqx.onrender.com", agent_id="procurement-bot")
guard.new_session()

result = guard.intercept_raw(input_text, output_text)

if result.threat_level == "CRITICAL" or result.policy_violations:
    raise GovernanceException(result)

# result.threat_level      → "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
# result.fired_threats     → ["data_exfiltration", "policy_bypass"]
# result.policy_violations → [{"policy_id": "no-pii-export", ...}]
# result.allowed           → True / False
````

---

## Decorator Pattern

````python
@guard.watch()
def run_agent(task: str) -> str:
    return your_llm_call(task)

# Pulse intercepts every call automatically
run_agent("summarise purchase orders for Q2")
````

---

## Methods

| Method | Returns | Description |
|---|---|---|
| `new_session()` | `str` | Start a new governance session |
| `intercept(input, output)` | `str` | Intercept and govern an agent turn |
| `intercept_raw(input, output)` | `PulseResult` | Intercept and return full governance result |
| `get_status()` | `dict` | Backend health and circuit breaker state |
| `watch()` | decorator | Wrap any agent function for auto-governance |

---

## PulseResult Fields

| Field | Type | Description |
|---|---|---|
| `threat_level` | `str` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `fired_threats` | `list` | Threat class names that fired |
| `policy_violations` | `list` | Org policy violations detected |
| `allowed` | `bool` | Whether the action was allowed |
| `blocked` | `bool` | Whether the circuit breaker blocked it |

---

## ASEAN Compliance Coverage

| Framework | Jurisdiction | Window |
|---|---|---|
| PDPA Malaysia | MY | 24 hours |
| Singapore Model AI Governance | SG | 72 hours |
| Vietnam AI Law | VN | 72 hours |

Pulse maps every governance event to the correct regulatory obligation automatically.

---

## Fail-Open Design

If the Pulse backend is unreachable, `fail_open=True` (default) passes the request through without blocking. Your agent never goes down because of Pulse.

````python
guard = PulseGuard("https://pulse-proxy-8dqx.onrender.com", agent_id="my-agent", fail_open=True)
````

---

## CI Status

![Pulse SDK Tests](https://github.com/nazirwaqas163-svg/waqasnazir92/actions/workflows/main.yml/badge.svg)

---

*Pulse — Immutable AI Governance for ASEAN · Built by Waqas Nazir*
