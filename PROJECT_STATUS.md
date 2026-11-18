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
- Replay verifies individual event hashes but does not assert complete-chain integrity or external anchoring.
- Tenant-scoped trace ingestion and lookup are implemented at `/v1/traces`; apply `migrations/0002_agent_traces.sql` to Supabase before using those endpoints.
- Agent isolation and release records are now scoped by organization; dashboards pass the selected organization when listing or releasing an agent.

## Known production gaps

Sessions, isolation, and circuit-breaker state remain process-local. Durable shared state, evaluation workflows, agent registry/approval, alert integrations, and SSO require later stages and supporting infrastructure. Trace ingestion requires applying its SQL migration. See [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md).

## Local development

Install `requirements.txt`, then run the API with `uvicorn main:app --host 127.0.0.1 --port 8000`. Serve the static dashboard from `frontend/` using the included server. Configure Supabase, org/admin credentials, and model upstream secrets in the environment before exercising protected production flows.

