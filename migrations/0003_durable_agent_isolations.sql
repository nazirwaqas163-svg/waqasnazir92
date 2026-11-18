-- Durable, tenant-scoped quarantine state for production deployments.
-- Apply with the Supabase SQL editor before setting
-- PULSE_DURABLE_ISOLATION_ENABLED=true on the API service.
create table if not exists public.agent_isolations (
    org_id text not null,
    agent_id text not null,
    reason text not null,
    hold_id text,
    isolated_at timestamptz not null default now(),
    released_at timestamptz,
    released_by text,
    primary key (org_id, agent_id)
);

create index if not exists agent_isolations_org_active_idx
    on public.agent_isolations (org_id, isolated_at desc)
    where released_at is null;

alter table public.agent_isolations enable row level security;
revoke all on public.agent_isolations from anon, authenticated;
grant select, insert, update, delete on public.agent_isolations to service_role;

