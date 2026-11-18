-- Tenant-scoped versioned agent inventory and auditable approval workflow.

create table if not exists public.agent_governance_versions (
    org_id text not null,
    agent_id text not null,
    agent_version text not null,
    name text not null,
    owner text not null,
    environment text not null check (environment in ('development', 'staging', 'production')),
    model_version text not null,
    prompt_version text not null,
    risk_tier text not null check (risk_tier in ('low', 'medium', 'high', 'critical')),
    data_classification text not null check (data_classification in ('public', 'internal', 'confidential', 'restricted')),
    scope text[] not null default '{}',
    metadata jsonb not null default '{}'::jsonb,
    approval_status text not null default 'pending' check (approval_status in ('pending', 'approved', 'rejected')),
    created_by text not null,
    created_at timestamptz not null default now(),
    reviewed_by text,
    reviewed_at timestamptz,
    review_notes text,
    primary key (org_id, agent_id, agent_version)
);

create index if not exists agent_governance_org_created_idx
    on public.agent_governance_versions (org_id, created_at desc);
create index if not exists agent_governance_org_agent_status_idx
    on public.agent_governance_versions (org_id, agent_id, approval_status, created_at desc);

create table if not exists public.agent_governance_events (
    event_id uuid primary key default gen_random_uuid(),
    org_id text not null,
    agent_id text not null,
    agent_version text not null,
    action text not null check (action in ('submitted', 'approved', 'rejected')),
    actor text not null,
    notes text,
    created_at timestamptz not null default now(),
    foreign key (org_id, agent_id, agent_version)
        references public.agent_governance_versions (org_id, agent_id, agent_version)
);

create index if not exists agent_governance_events_version_created_idx
    on public.agent_governance_events (org_id, agent_id, agent_version, created_at asc);

create or replace function public.pulse_submit_agent_version(
    p_org_id text,
    p_agent_id text,
    p_agent_version text,
    p_name text,
    p_owner text,
    p_environment text,
    p_model_version text,
    p_prompt_version text,
    p_risk_tier text,
    p_data_classification text,
    p_scope text[],
    p_metadata jsonb,
    p_created_by text
) returns setof public.agent_governance_versions
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
    insert into public.agent_governance_versions (
        org_id, agent_id, agent_version, name, owner, environment, model_version,
        prompt_version, risk_tier, data_classification, scope, metadata, created_by
    ) values (
        p_org_id, p_agent_id, p_agent_version, p_name, p_owner, p_environment,
        p_model_version, p_prompt_version, p_risk_tier, p_data_classification,
        coalesce(p_scope, '{}'), coalesce(p_metadata, '{}'::jsonb), p_created_by
    );
    insert into public.agent_governance_events (
        org_id, agent_id, agent_version, action, actor
    ) values (p_org_id, p_agent_id, p_agent_version, 'submitted', p_created_by);
    return query
        select * from public.agent_governance_versions
        where org_id = p_org_id and agent_id = p_agent_id and agent_version = p_agent_version;
end;
$$;

create or replace function public.pulse_review_agent_version(
    p_org_id text,
    p_agent_id text,
    p_agent_version text,
    p_decision text,
    p_reviewer text,
    p_notes text
) returns setof public.agent_governance_versions
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
    if p_decision not in ('approved', 'rejected') then
        raise exception 'decision must be approved or rejected';
    end if;
    update public.agent_governance_versions
       set approval_status = p_decision,
           reviewed_by = p_reviewer,
           reviewed_at = now(),
           review_notes = p_notes
     where org_id = p_org_id
       and agent_id = p_agent_id
       and agent_version = p_agent_version
       and approval_status = 'pending';
    if not found then
        raise exception 'agent version was not found or is no longer pending';
    end if;
    insert into public.agent_governance_events (
        org_id, agent_id, agent_version, action, actor, notes
    ) values (p_org_id, p_agent_id, p_agent_version, p_decision, p_reviewer, p_notes);
    return query
        select * from public.agent_governance_versions
        where org_id = p_org_id and agent_id = p_agent_id and agent_version = p_agent_version;
end;
$$;

create or replace function public.reject_agent_governance_event_mutation()
returns trigger
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
    raise exception 'agent governance history is append-only';
end;
$$;

create trigger agent_governance_events_append_only
    before update or delete on public.agent_governance_events
    for each row execute function public.reject_agent_governance_event_mutation();

alter table public.agent_governance_versions enable row level security;
alter table public.agent_governance_events enable row level security;
revoke all on public.agent_governance_versions, public.agent_governance_events from public, anon, authenticated;
grant select, insert, update on public.agent_governance_versions to service_role;
grant select, insert on public.agent_governance_events to service_role;
revoke all on function public.pulse_submit_agent_version(text, text, text, text, text, text, text, text, text, text, text[], jsonb, text) from public, anon, authenticated;
grant execute on function public.pulse_submit_agent_version(text, text, text, text, text, text, text, text, text, text, text[], jsonb, text) to service_role;
revoke all on function public.pulse_review_agent_version(text, text, text, text, text, text) from public, anon, authenticated;
grant execute on function public.pulse_review_agent_version(text, text, text, text, text, text) to service_role;
