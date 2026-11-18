-- First-class GenAI provider, model, token, and cost attributes on trace spans.
alter table public.agent_traces
    add column if not exists provider text,
    add column if not exists model text,
    add column if not exists input_tokens bigint check (input_tokens is null or input_tokens >= 0),
    add column if not exists output_tokens bigint check (output_tokens is null or output_tokens >= 0),
    add column if not exists total_tokens bigint check (total_tokens is null or total_tokens >= 0),
    add column if not exists cost_usd numeric(18, 8) check (cost_usd is null or cost_usd >= 0);

create index if not exists agent_traces_org_provider_model_started_idx
    on public.agent_traces (org_id, provider, model, started_at desc);
