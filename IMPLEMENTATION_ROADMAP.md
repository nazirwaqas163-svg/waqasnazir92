# Product quality roadmap

This roadmap translates the product review into deliverable stages. Arthur, Credo, and Fiddler are useful references for continuous evaluation, lifecycle governance, and production observability; Pulse should differentiate through inline agent controls and evidence customers can independently verify.

## Delivered in this change

- Require a verified organization API key for interception and customer event feeds. Anonymous demo traffic is opt-in (`PULSE_ALLOW_ANONYMOUS_DEMO=true`).
- Store newly issued organization keys as SHA-256 digests and retain legacy key lookup temporarily for rotation.
- Add named dashboard principals with viewer, operator, and admin roles through `PULSE_ADMIN_KEYS_JSON`; keep the legacy shared key as a temporary admin migration path.
- Make health report readiness and degraded dependencies when Supabase or the upstream model is unavailable, or shadow mode is enabled.
- Verify persisted event row hashes and label replay results as partial evidence when complete chain and external anchoring are not verified.
- Make the SDK fail closed by default and correct the dashboard and docs to describe the guarantees actually provided.
- Add tenant-scoped OpenTelemetry-style span ingestion, recent trace retrieval, trace detail lookup, bounded payload validation, and SDK support. Apply `migrations/0002_agent_traces.sql` before enabling these endpoints in production.
- Scope agent isolation and release decisions by organization so identical agent IDs in separate tenants do not affect one another.
- Add Supabase-backed durable quarantine state behind `PULSE_DURABLE_ISOLATION_ENABLED`; when enabled, DB errors fail closed and health reports whether the durable path is active. Apply `migrations/0003_durable_agent_isolations.sql` before enabling it.
- Add optional durable tenant session state with versioned optimistic writes for BDI history and baseline counts. Enable with `PULSE_DURABLE_SESSION_STATE_ENABLED=true` after applying `migrations/0004_durable_agent_sessions.sql`; write conflicts retry and storage errors fail closed.
- Add shared durable circuit-breaker state. Enable with `PULSE_DURABLE_CIRCUIT_BREAKER_ENABLED=true` after applying `migrations/0005_durable_circuit_breaker.sql`; every gated request synchronizes with shared storage and fails closed when that store is unavailable.

## Next: reliability foundation

1. Add append-only audit storage with monotonic sequence, complete-chain verification, periodic external anchoring, and key rotation. A row hash alone does not prove completeness or resist a privileged database rewrite.
2. Add service-level auth/rate limits, origin restrictions for browser access, structured audit export, and secret rotation with revocation dates for legacy plaintext org keys.

## Then: observability and evaluation

1. Extend trace ingestion with standardized GenAI semantic attributes, provider/model metadata, token/cost fields, and correlated policy decisions; add retention and redaction controls.
2. Add versioned evaluation datasets, configurable evaluators, regression runs, thresholds, and release gates. Keep evaluator results linked to prompt/model/agent versions.
3. Add configurable alert rules and delivery integrations with retries, deduplication, and delivery history.

## Then: governance lifecycle

1. Add an agent/model registry with owners, versions, environments, data classifications, risk assessments, and approval history.
2. Add review workflows for policy/model changes, deployment approvals, periodic recertification, and evidence packages tied to a versioned control set.
3. Add enterprise identity (OIDC/SAML), organization membership, scoped roles, and auditable access changes. The current role keys are a bootstrap mechanism, not an SSO implementation.

## Release gates

- Add automated unit and API tests for tenant isolation, authorization matrix, fail-closed SDK behavior, key rotation, health readiness, and audit verification.
- Require passing CI and a human review before merging to `master`; enable branch protection in GitHub.
- Configure production secrets and durable storage before enabling anonymous traffic or deploying multi-worker service instances.
- Validate production health, tenant isolation, interception, and rollback after deployment.

The later stages require product decisions and external service configuration. They are not represented as complete by this code change.

