-- Tenant-scoped OpenTelemetry-style spans.
-- Apply with the Supabase SQL editor before enabling the /v1/traces API.
create table if not exists public.agent_traces (
    org_id text not null,
    trace_id text not null check (trace_id ~ '^[0-9a-f]{32}$'),
    span_id text not null check (span_id ~ '^[0-9a-f]{16}$'),
    parent_span_id text check (parent_span_id is null or parent_span_id ~ '^[0-9a-f]{16}$'),
    name text not null,
    kind text not null check (kind in ('internal', 'server', 'client', 'producer', 'consumer')),
    started_at timestamptz not null,
    ended_at timestamptz not null check (ended_at >= started_at),
    status text not null check (status in ('unset', 'ok', 'error')),
    agent_id text,
    resource jsonb not null default '{}'::jsonb,
    attributes jsonb not null default '{}'::jsonb,
    events jsonb not null default '[]'::jsonb,
    ingested_at timestamptz not null default now(),
    primary key (org_id, trace_id, span_id)
);

create index if not exists agent_traces_org_started_idx
    on public.agent_traces (org_id, started_at desc);
create index if not exists agent_traces_org_trace_started_idx
    on public.agent_traces (org_id, trace_id, started_at asc);
create index if not exists agent_traces_org_agent_started_idx
    on public.agent_traces (org_id, agent_id, started_at desc);

alter table public.agent_traces enable row level security;
revoke all on public.agent_traces from anon, authenticated;
grant select, insert, update, delete on public.agent_traces to service_role;

