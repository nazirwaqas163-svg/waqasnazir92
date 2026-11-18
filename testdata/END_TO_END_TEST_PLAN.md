# Pulse synthetic verification plan

Use this checklist only against a dedicated staging API, staging organization, and synthetic credentials. Do not run state-changing steps against production. All names and payloads in this plan are fictional.

The deterministic evaluation inputs are in [synthetic_evaluation_datasets.json](synthetic_evaluation_datasets.json). Import them through the evaluation workbench or the documented API. Expected case counts, pass rates, and release-gate outcomes are included with each dataset.

## Before the run

- Record the staging API base URL, build/commit, UTC start time, and feature flags.
- Confirm the API is connected to a staging Supabase project and the durable isolation flag is enabled.
- Create/use a dedicated test organization. Never copy a production API key or admin key into this run.
- Ensure the agent IDs below are reserved for this test organization.
- Save a baseline count of test-org traces, agent versions, evaluation datasets/runs, and isolation records.

## Scenarios and expected outcomes

| Scenario | Action | Expected result |
|---|---|---|
| Access control | Request a protected operation without credentials, then with an invalid key | Requests are rejected; no test records are created. |
| Organization context | Fetch context with the staging organization key | The response identifies the test organization. |
| Agent activity | Submit a safe synthetic intercept for `synthetic-onboarding-agent` | A normal decision is returned and the dashboard shows the event/session. |
| Traces | Ingest a deterministic batch of two spans with a fixed trace ID, repeat it, then query by trace ID | Valid spans are visible to the test org; duplicate submission follows the documented idempotency behavior; another org cannot read them. |
| Evaluation pass | Import the baseline dataset and run at 100% threshold | 5/5 pass and gate passes. |
| Evaluation block | Import the release-gate dataset and run at 80% threshold | 3/5 pass (60%) and gate blocks. |
| Evaluation edge cases | Import the normalization dataset and run at 75% threshold | 3/4 pass (75%) and gate passes; malformed JSON is reported as a failed case rather than crashing the run. |
| Governance review | Submit a synthetic agent version, approve it with the admin credential, then inspect its history | It starts pending, records the review, and is visible only within the test org. |
| Isolation lifecycle | Isolate the test agent with a reason, send a synthetic intercept, release it, then send another safe intercept | Isolation is recorded; the isolated request is rejected with 423; release is recorded; the later safe request succeeds. |
| Isolation durability | Restart the staging API while the test agent is isolated, then re-check and attempt intercept | Isolation remains active after restart and still blocks execution. |
| Compliance | Fetch the staging compliance deadline view, with and without a synthetic incident time | The dashboard shows a valid status or an explicit empty state; invalid inputs produce a clear error. |
| Passport | Download the passport through the dashboard | The authenticated request downloads a PDF; opening the API URL directly without an admin key remains rejected. |
| Circuit breaker | Open the staging breaker, verify a safe test request is blocked according to policy, and always close it in cleanup | State changes are visible and the breaker is closed after the test, including on failure. |
| UI recovery | Remove a test credential, revisit protected sections, then restore it | Missing access is explained; restoring credentials recovers the view without stale error state. |

## Evidence to capture

For each row, record pass/fail, request ID, HTTP status, a redacted response summary, dashboard screenshot or view, and the matching test-org record. Never store API keys, admin keys, personal data, or raw secrets in the report.

## Cleanup

- Release every test isolation.
- Close the circuit breaker even if an earlier step fails.
- Delete only test-organization records if the product supports safe tenant-scoped deletion; otherwise label them as synthetic staging data and retain the run ID for later cleanup.
- Confirm no test rows appeared under a non-test organization.
