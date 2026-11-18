# Pulse project status

## Current service

- Dashboard: https://pulse-dashboard-cx7x.onrender.com/index.html
- Repository: https://github.com/nazirwaqas163-svg/waqasnazir92
- Backend health endpoint: `/health`
- Main implementation: `main.py`; dashboard: `frontend/index.html`; SDK: `pulse_sdk.py`

## Security and operating model

- Customer interception and event-feed requests require a valid organization API key, unless `PULSE_ALLOW_ANONYMOUS_DEMO=true` is explicitly set.
- Dashboard APIs require `PULSE_ADMIN_API_KEY` or an entry in `PULSE_ADMIN_KEYS_JSON`. The latter supports `viewer`, `operator`, and `admin` roles.
- New org keys are stored as SHA-256 digests. Existing plaintext keys are accepted only as a migration path and should be rotated.
- SDK enforcement defaults to fail closed. Set `fail_open=True` only for workloads whose risk policy permits bypassing Pulse when it is unavailable.
- `/health` reports degraded readiness when required dependencies are unavailable; inspect `degraded_reasons` and `dependencies`.
- Audit rows now have an append-only database guard and monotonic ledger sequence after applying `migrations/0006_append_only_audit_ledger.sql`. The integrity endpoint detects missing sequence values and broken adjacent links; historical completeness and external anchoring remain unverified.
- Tenant-scoped trace ingestion and lookup are implemented at `/v1/traces`; apply `migrations/0002_agent_traces.sql` to Supabase before using those endpoints.
- Agent isolation and release records are now scoped by organization; dashboards pass the selected organization when listing or releasing an agent.
- Durable isolation is available after applying `migrations/0003_durable_agent_isolations.sql` and enabling `PULSE_DURABLE_ISOLATION_ENABLED=true`. With the flag off, isolation remains process-local and `/health` reports degraded readiness.
- Durable BDI history and baseline counts are available after applying `migrations/0004_durable_agent_sessions.sql` and enabling `PULSE_DURABLE_SESSION_STATE_ENABLED=true`. Version conflicts retry; storage failures return 503.
- Shared circuit-breaker state is available after applying `migrations/0005_durable_circuit_breaker.sql` and enabling `PULSE_DURABLE_CIRCUIT_BREAKER_ENABLED=true`. Gated requests synchronize with Supabase; unavailable storage returns 503.

- Versioned evaluation datasets, deterministic evaluators, immutable run history, and pass-rate release gates are available after applying `migrations/0007_versioned_evaluations.sql` and enabling `PULSE_EVALUATIONS_ENABLED=true`. Requests use tenant API keys and persist agent/prompt/model version metadata.

## Known production gaps

Registry and approval lifecycle, alert delivery integrations, independent audit anchoring and key rotation, and enterprise SSO still require later implementation and supporting infrastructure. Trace ingestion, durable isolation, durable sessions, and the durable breaker require applying their SQL migrations before enabling the corresponding flags. See [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md).

## Local development

Install `requirements.txt`, then run the API with `uvicorn main:app --host 127.0.0.1 --port 8000`. Serve the static dashboard from `frontend/` using the included server. Configure Supabase, org/admin credentials, and model upstream secrets in the environment before exercising protected production flows.

