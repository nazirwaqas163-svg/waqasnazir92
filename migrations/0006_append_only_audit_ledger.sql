-- Add ordered, append-only audit ledger columns.
-- Existing hashes remain intact; this migration does not retroactively prove historical completeness.

alter table public.ai_events
    add column if not exists ledger_sequence bigint generated always as identity;
create unique index if not exists ai_events_ledger_sequence_uq
    on public.ai_events (ledger_sequence);

alter table public.audit_logs
    add column if not exists ledger_sequence bigint generated always as identity;
create unique index if not exists audit_logs_ledger_sequence_uq
    on public.audit_logs (ledger_sequence);

create or replace function public.reject_audit_ledger_mutation()
returns trigger
language plpgsql
as $$
begin
    raise exception 'audit ledgers are append-only';
end;
$$;

drop trigger if exists ai_events_append_only on public.ai_events;
create trigger ai_events_append_only
    before update or delete on public.ai_events
    for each row execute function public.reject_audit_ledger_mutation();

drop trigger if exists audit_logs_append_only on public.audit_logs;
create trigger audit_logs_append_only
    before update or delete on public.audit_logs
    for each row execute function public.reject_audit_ledger_mutation();

alter table public.ai_events enable row level security;
alter table public.audit_logs enable row level security;
revoke update, delete, truncate on public.ai_events, public.audit_logs from public, anon, authenticated, service_role;
grant select, insert on public.ai_events, public.audit_logs to service_role;
