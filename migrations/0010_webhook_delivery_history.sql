-- Durable idempotency and delivery history for signed alert webhooks.

create table if not exists public.webhook_delivery_logs (
    delivery_key text primary key,
    org_id text not null,
    registration_id uuid not null,
    event_type text not null,
    event_reference text not null,
    status text not null default 'pending' check (status in ('pending', 'delivered', 'failed')),
    attempt_count integer not null default 0 check (attempt_count >= 0),
    response_status integer,
    last_error text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    delivered_at timestamptz
);

create index if not exists webhook_delivery_logs_org_created_idx
    on public.webhook_delivery_logs (org_id, created_at desc);
create index if not exists webhook_delivery_logs_status_updated_idx
    on public.webhook_delivery_logs (status, updated_at);

create or replace function public.pulse_claim_webhook_delivery(
    p_delivery_key text,
    p_org_id text,
    p_registration_id uuid,
    p_event_type text,
    p_event_reference text
) returns boolean
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
declare
    claimed text;
begin
    insert into public.webhook_delivery_logs (
        delivery_key, org_id, registration_id, event_type, event_reference, status
    ) values (
        p_delivery_key, p_org_id, p_registration_id, p_event_type, p_event_reference, 'pending'
    )
    on conflict (delivery_key) do update
       set status = 'pending',
           updated_at = now(),
           last_error = null
     where public.webhook_delivery_logs.status = 'failed'
        or (
            public.webhook_delivery_logs.status = 'pending'
            and public.webhook_delivery_logs.updated_at < now() - interval '5 minutes'
        )
    returning delivery_key into claimed;
    return claimed is not null;
end;
$$;

alter table public.webhook_delivery_logs enable row level security;
revoke all on public.webhook_delivery_logs from public, anon, authenticated;
grant select, insert, update on public.webhook_delivery_logs to service_role;
revoke all on function public.pulse_claim_webhook_delivery(text, text, uuid, text, text) from public, anon, authenticated;
grant execute on function public.pulse_claim_webhook_delivery(text, text, uuid, text, text) to service_role;
