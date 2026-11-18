-- Durable, system-wide circuit-breaker state.
-- Apply before setting PULSE_DURABLE_CIRCUIT_BREAKER_ENABLED=true.

create table if not exists public.circuit_breaker_state (
    singleton_id boolean primary key default true check (singleton_id),
    state text not null default 'closed' check (state in ('closed', 'open')),
    reason text not null default 'initial state',
    bdi_score double precision not null default 0,
    entropy double precision not null default 0,
    opened_at timestamptz,
    updated_at timestamptz not null default now()
);

insert into public.circuit_breaker_state (singleton_id, state, reason)
values (true, 'closed', 'initial state')
on conflict (singleton_id) do nothing;

alter table public.circuit_breaker_state enable row level security;
revoke all on public.circuit_breaker_state from public, anon, authenticated;
grant select, insert, update on public.circuit_breaker_state to service_role;
