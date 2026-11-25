-- RLS Guard: read-only audit queries for Supabase / Postgres.
-- Adjust the schema list if the project exposes more than `public` in its API settings.

-- 1. Tables with RLS off in exposed schemas
select n.nspname as schema, c.relname as table, c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p')
  and n.nspname in ('public')
order by c.relrowsecurity, n.nspname, c.relname;

-- 2. Every policy, with its roles and expressions
select schemaname, tablename, policyname, cmd, roles, permissive, qual as using_expr, with_check
from pg_policies
where schemaname in ('public', 'storage')
order by schemaname, tablename, cmd;

-- 3. Tables with RLS on but no policy (deny-all: safe but likely broken feature)
select n.nspname as schema, c.relname as table
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p') and c.relrowsecurity
  and n.nspname in ('public')
  and not exists (select 1 from pg_policies p where p.schemaname = n.nspname and p.tablename = c.relname);

-- 4. Suspicious policies: always-true, user_metadata, with_check different from using.
--    A NULL with_check is fine (Postgres reuses USING); a different one needs reading.
select schemaname, tablename, policyname, cmd, roles, qual, with_check,
  case
    when qual = 'true' or with_check = 'true' then 'always true'
    when coalesce(qual, '') || coalesce(with_check, '') ilike '%user_metadata%' then 'uses user_metadata'
    when cmd in ('UPDATE', 'ALL') and with_check is not null and with_check <> qual then 'with_check differs from using: read it'
  end as issue
from pg_policies
where schemaname in ('public', 'storage')
  and (
    qual = 'true' or with_check = 'true'
    or coalesce(qual, '') || coalesce(with_check, '') ilike '%user_metadata%'
    or (cmd in ('UPDATE', 'ALL') and with_check is not null and with_check <> qual)
  );

-- 5. Views that bypass RLS (no security_invoker)
select n.nspname as schema, c.relname as view, c.reloptions
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('v', 'm')
  and n.nspname in ('public')
  and not coalesce(c.reloptions::text ilike '%security_invoker=true%', false);

-- 6. SECURITY DEFINER functions reachable through /rpc
select n.nspname as schema, p.proname as function, pg_get_function_identity_arguments(p.oid) as args,
  p.proconfig as settings,  -- look for search_path here
  has_function_privilege('anon', p.oid, 'execute') as anon_can_execute,
  has_function_privilege('authenticated', p.oid, 'execute') as authenticated_can_execute
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname in ('public');

-- 7. Storage buckets
select id, name, public, file_size_limit, allowed_mime_types from storage.buckets;

-- 8. Direct grants to anon (RLS still applies, but this shows the attack surface)
select table_schema, table_name, string_agg(privilege_type, ', ') as privileges
from information_schema.role_table_grants
where grantee = 'anon' and table_schema in ('public')
group by table_schema, table_name
order by table_name;

-- 9. Sensitive columns a signed-in user can really change: column grant AND an UPDATE/ALL policy.
--    RLS limits rows, not columns. Without an UPDATE policy the grant is harmless, so those are filtered out.
select c.table_name, c.column_name
from information_schema.columns c
where c.table_schema = 'public'
  and c.column_name ~* '(role|plan|tier|admin|tenant|org_id|token|secret|stripe|credit|quota|balance|verified|status)'
  and has_column_privilege('authenticated', format('%I.%I', c.table_schema, c.table_name), c.column_name, 'UPDATE')
  and exists (select 1 from pg_policies p
              where p.schemaname = c.table_schema and p.tablename = c.table_name
                and p.cmd in ('UPDATE', 'ALL')
                and (p.roles && array['authenticated', 'public']::name[]))
order by c.table_name, c.column_name;

-- 10. Bodies of SECURITY DEFINER functions that take a user id: each must check it against auth.uid()
select p.proname, pg_get_functiondef(p.oid)
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname = 'public'
  and pg_get_function_identity_arguments(p.oid) ~* 'user|uid|owner|tenant';
