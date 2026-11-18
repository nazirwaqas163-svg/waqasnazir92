-- Durable, tenant-scoped quarantine state for production deployments.
-- Apply with the Supabase SQL editor before setting
-- PULSE_DURABLE_ISOLATION_ENABLED=true on the API service.
create table if not exists public.agent_isolations (
    org_id text not null check (char_length(org_id) between 1 and 256),
    agent_id text not null check (char_length(agent_id) between 1 and 256),
    reason text not null check (char_length(reason) <= 2000),
    hold_id text check (hold_id is null or char_length(hold_id) <= 256),
    isolated_at timestamptz not null default now(),
    released_at timestamptz,
    released_by text check (released_by is null or char_length(released_by) <= 256),
    primary key (org_id, agent_id)
);

create index if not exists agent_isolations_org_active_idx
    on public.agent_isolations (org_id, isolated_at desc)
    where released_at is null;

alter table public.agent_isolations enable row level security;
revoke all on public.agent_isolations from anon, authenticated;
grant select, insert, update, delete on public.agent_isolations to service_role;

