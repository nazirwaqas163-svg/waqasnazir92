-- Server-side service-role access only for existing public data tables.
-- The application uses the Supabase service role from its API server; no browser client
-- should access these tables directly.

alter table public.agent_registry enable row level security;
alter table public.legal_holds enable row level security;
alter table public.org_policies enable row level security;
alter table public.webhook_registrations enable row level security;
alter table public.incident_reports enable row level security;
alter table public.orgs enable row level security;
alter table public.replay_sessions enable row level security;
revoke all on table public.agent_registry, public.legal_holds, public.org_policies, public.webhook_registrations, public.incident_reports, public.orgs, public.replay_sessions from public, anon, authenticated;
grant select, insert, update, delete on table public.agent_registry, public.legal_holds, public.org_policies, public.webhook_registrations, public.incident_reports, public.orgs, public.replay_sessions to service_role;
