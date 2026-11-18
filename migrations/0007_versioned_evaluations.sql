-- Versioned, tenant-scoped evaluation datasets and immutable run records.

create table if not exists public.evaluation_datasets (
    org_id text not null,
    dataset_id uuid not null,
    dataset_version integer not null check (dataset_version > 0),
    name text not null,
    agent_id text not null,
    agent_version text not null,
    prompt_version text not null,
    model_version text not null,
    cases jsonb not null check (jsonb_typeof(cases) = 'array' and jsonb_array_length(cases) between 1 and 1000),
    created_by text not null,
    created_at timestamptz not null default now(),
    primary key (org_id, dataset_id, dataset_version)
);

create index if not exists evaluation_datasets_org_created_idx
    on public.evaluation_datasets (org_id, created_at desc);
create index if not exists evaluation_datasets_org_id_version_idx
    on public.evaluation_datasets (org_id, dataset_id, dataset_version desc);

create table if not exists public.evaluation_runs (
    run_id uuid primary key default gen_random_uuid(),
    org_id text not null,
    dataset_id uuid not null,
    dataset_version integer not null,
    agent_id text not null,
    agent_version text not null,
    prompt_version text not null,
    model_version text not null,
    evaluator_config jsonb not null default '{}'::jsonb,
    case_count integer not null check (case_count > 0),
    passed_count integer not null check (passed_count between 0 and case_count),
    pass_rate double precision not null check (pass_rate between 0 and 1),
    minimum_pass_rate double precision not null check (minimum_pass_rate between 0 and 1),
    release_gate_passed boolean not null,
    results jsonb not null check (jsonb_typeof(results) = 'array'),
    created_at timestamptz not null default now(),
    foreign key (org_id, dataset_id, dataset_version)
        references public.evaluation_datasets (org_id, dataset_id, dataset_version)
);

create index if not exists evaluation_runs_org_created_idx
    on public.evaluation_runs (org_id, created_at desc);
create index if not exists evaluation_runs_org_dataset_idx
    on public.evaluation_runs (org_id, dataset_id, dataset_version, created_at desc);

create or replace function public.create_evaluation_dataset_version(
    p_org_id text,
    p_dataset_id uuid,
    p_name text,
    p_agent_id text,
    p_agent_version text,
    p_prompt_version text,
    p_model_version text,
    p_cases jsonb,
    p_created_by text
)
returns setof public.evaluation_datasets
language plpgsql
as $$
declare
    next_version integer;
begin
    if jsonb_typeof(p_cases) <> 'array'
       or jsonb_array_length(p_cases) < 1
       or jsonb_array_length(p_cases) > 1000 then
        raise exception 'cases must be an array with 1 to 1000 entries';
    end if;
    perform pg_advisory_xact_lock(hashtext(p_org_id || ':' || p_dataset_id::text));
    select coalesce(max(dataset_version), 0) + 1 into next_version
      from public.evaluation_datasets
     where org_id = p_org_id and dataset_id = p_dataset_id;
    return query
    insert into public.evaluation_datasets (
        org_id, dataset_id, dataset_version, name, agent_id, agent_version,
        prompt_version, model_version, cases, created_by
    ) values (
        p_org_id, p_dataset_id, next_version, p_name, p_agent_id, p_agent_version,
        p_prompt_version, p_model_version, p_cases, p_created_by
    )
    returning *;
end;
$$;

alter table public.evaluation_datasets enable row level security;
alter table public.evaluation_runs enable row level security;
revoke all on public.evaluation_datasets, public.evaluation_runs from public, anon, authenticated;
grant select, insert on public.evaluation_datasets, public.evaluation_runs to service_role;
revoke all on function public.create_evaluation_dataset_version(text, uuid, text, text, text, text, text, jsonb, text) from public, anon, authenticated;
grant execute on function public.create_evaluation_dataset_version(text, uuid, text, text, text, text, text, jsonb, text) to service_role;
