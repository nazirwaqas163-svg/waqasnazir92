-- Durable tenant-scoped BDI and baseline state.
-- Apply before setting PULSE_DURABLE_SESSION_STATE_ENABLED=true.
create table if not exists public.agent_sessions (
    org_id text not null,
    session_id text not null,
    agent_id text not null,
    turn_count integer not null default 0 check (turn_count >= 0),
    bdi_score double precision not null default 0 check (bdi_score between 0 and 1),
    seen_risk jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    version bigint not null default 1,
    primary key (org_id, session_id)
);

create index if not exists agent_sessions_org_agent_last_seen_idx
    on public.agent_sessions (org_id, agent_id, last_seen_at desc);

alter table public.agent_sessions enable row level security;
revoke all on public.agent_sessions from anon, authenticated;
grant select, insert, update, delete on public.agent_sessions to service_role;

create or replace function public.pulse_write_agent_session(
    p_org_id text,
    p_session_id text,
    p_agent_id text,
    p_expected_version bigint,
    p_turn_count integer,
    p_bdi_score double precision,
    p_seen_risk jsonb,
    p_created_at timestamptz,
    p_last_seen_at timestamptz
) returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
    changed integer;
begin
    if p_expected_version = 0 then
        insert into public.agent_sessions (
            org_id, session_id, agent_id, turn_count, bdi_score, seen_risk,
            created_at, last_seen_at, version
        ) values (
            p_org_id, p_session_id, p_agent_id, p_turn_count, p_bdi_score,
            p_seen_risk, p_created_at, p_last_seen_at, 1
        ) on conflict (org_id, session_id) do nothing;
    else
        update public.agent_sessions
        set agent_id = p_agent_id,
            turn_count = p_turn_count,
            bdi_score = p_bdi_score,
            seen_risk = p_seen_risk,
            last_seen_at = p_last_seen_at,
            version = version + 1
        where org_id = p_org_id
          and session_id = p_session_id
          and version = p_expected_version;
    end if;
    get diagnostics changed = row_count;
    return changed = 1;
end;
$$;

revoke all on function public.pulse_write_agent_session(
    text, text, text, bigint, integer, double precision, jsonb, timestamptz, timestamptz
) from public, anon, authenticated;
grant execute on function public.pulse_write_agent_session(
    text, text, text, bigint, integer, double precision, jsonb, timestamptz, timestamptz
) to service_role;

