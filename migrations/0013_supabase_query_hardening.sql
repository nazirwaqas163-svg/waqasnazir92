-- Add covering indexes for existing org foreign keys and optimize service-role RLS checks.

create index if not exists agent_registry_org_id_idx on public.agent_registry (org_id);
create index if not exists ai_events_org_id_idx on public.ai_events (org_id);
create index if not exists audit_logs_org_id_idx on public.audit_logs (org_id);
create index if not exists incident_reports_org_id_idx on public.incident_reports (org_id);
create index if not exists legal_holds_org_id_idx on public.legal_holds (org_id);
create index if not exists webhook_delivery_logs_registration_id_idx
    on public.webhook_delivery_logs (registration_id);

drop policy if exists service_role_all_ai_events on public.ai_events;
create policy service_role_all_ai_events on public.ai_events
    for all to public
    using ((select auth.role()) = 'service_role')
    with check ((select auth.role()) = 'service_role');

drop policy if exists service_role_all_audit_logs on public.audit_logs;
create policy service_role_all_audit_logs on public.audit_logs
    for all to public
    using ((select auth.role()) = 'service_role')
    with check ((select auth.role()) = 'service_role');
