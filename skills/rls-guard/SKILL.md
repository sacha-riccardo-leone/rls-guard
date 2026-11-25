---
name: rls-guard
description: Audit and fix database access rules in apps built on Supabase (Row Level Security, storage, RPC functions, exposed keys) or Firebase (Firestore/Storage rules). Finds tables anyone can read or write with the public key, policies that let one user touch another user's rows, and leaked service keys, then writes the fixes and proves them. Use when the user says /rls-guard, "is my Supabase secure", "check my RLS", "can users see each other's data", "audit my Firebase rules", or before launching an app that uses Supabase or Firebase.
---

# RLS Guard

The public (anon) key of a Supabase or Firebase app is in every visitor's browser. Anything the rules allow for that key, **anyone on the internet can do**. Your job: find what is open, prove it, close it, prove it is closed.

Subcommands: `/rls-guard audit` (default, changes nothing), `/rls-guard fix` (audit, then apply fixes after the user approves them), `/rls-guard test` (re-run the proofs only).

## Ground rules

- Only audit a project the user owns. Prefer a local or staging database. On production with real users, only read: skip the cross-user write tests and prove with anon-key reads, grants and policy text instead. Elsewhere, every write test runs inside `begin; … rollback;`.
- Never print the service_role key or any secret. Say where it is, not what it is.
- Every finding gets a proof (a query or request and its actual result), not a guess.
- Apply fixes as a migration file the user can review, not by hand in the dashboard.

## 1. Map the app (Supabase)

Find the data access first:
- Migrations / schema: `supabase/migrations/*.sql`, or ask Postgres directly (below). If a Supabase MCP server is connected, use its `list_tables` and `get_advisors` (security) tools; the advisors catch many of the issues below for free.
- Client code: grep for `.from(`, `.rpc(`, `.storage.from(`, `createClient(`.
- Keys: grep the whole repo (including `.env*`, build output, `NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*`) for `service_role` and for JWTs (`eyJ`). Decode the payload of any JWT found in client-reachable code; `"role":"service_role"` there is a **critical** finding.

## 2. Run the checks

Run `references/supabase-audit.sql` (read-only queries). Then judge each result with this table:

| Check | Severity | What it means |
|---|---|---|
| Table in an exposed schema (`public`, or any in the API settings) with RLS **off** | Critical | Anyone can read and write it with the anon key |
| service_role key in client-reachable code or git history | Critical | Full database bypass for anyone who opens dev tools |
| Policy `using (true)` / `with check (true)` for `anon` or `public` on a non-public-content table | Critical | Open to the internet |
| `authenticated` policy with `using (true)` on per-user data | High | Any signed-up user (sign-up is often open) sees everyone's rows |
| UPDATE/ALL policy whose `with check` is **weaker** than its `using` (e.g. `with check (true)`, or a check that ignores `user_id`/`tenant_id`) | High | A user can rewrite `user_id` to someone else, or move rows between tenants. Note: a *missing* `with check` is NOT this bug; Postgres then reuses `using` for the new row |
| Users can UPDATE (or SELECT) columns they should not: `role`, `plan`, `tenant_id`, `is_admin`, tokens, billing fields | High | RLS picks rows, not columns. A user who may update their own profile row can promote themselves unless column grants stop it. Check `has_column_privilege` (query 9) and what the browser actually needs |
| Policy reads `auth.jwt() -> 'user_metadata'` (or `raw_user_meta_data`) | High | Users can edit their own user_metadata; use `app_metadata` or a roles table |
| View in an exposed schema without `security_invoker = true` | High | Views run as their owner and skip RLS of the tables under them |
| `security definer` function in an exposed schema, executable by anon/authenticated | High | Callable via `/rpc/`, runs with owner rights. Read its body: if it takes a `p_user_id`-style argument, it must compare it to `auth.uid()`, or any user can act as any other. Set `search_path`, revoke execute or move it to a private schema. A function that `returns trigger` can't be called through `/rpc/`: downgrade to Info (still revoke for hygiene) |
| A secret was ever committed (check `git log -p` for `SERVICE`, `SECRET`, `eyJ`, `sb_secret_`) and the live value is still the same | Critical if repo public, High if private | Compare by hash (`sha256sum` of old vs current value), never print either. Removing it from the file doesn't un-leak it: rotate |
| Public storage bucket holding user files, or `storage.objects` policy without a path/owner check | High | Files readable or overwritable by others |
| RLS on, zero policies | Info | Safe (denies all) but the feature using it is probably broken |
| `auth.uid()` not wrapped as `(select auth.uid())`, or policy column not indexed | Perf | Re-evaluated per row; slow on big tables |

Firebase: read `firestore.rules`, `storage.rules`, `database.rules.json`. Flag `allow read, write: if true`, test-mode rules (`request.time < timestamp.date(…)`), rules that check `request.auth != null` but not `request.auth.uid == resource.data.<owner>`, and writes without field validation. The Firebase web API key being public is normal, not a finding.

## 3. Prove it like an attacker

For every Critical/High finding, show it is real with the public key only:

```bash
# read
curl -s "$SUPABASE_URL/rest/v1/<table>?select=*&limit=3" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"
```

For cross-user checks, run in SQL inside a rolled-back transaction:

```sql
begin;
set local role authenticated;
set local request.jwt.claims = '{"sub":"<user-A-uuid>","role":"authenticated"}';
select count(*) from <table> where user_id <> '<user-A-uuid>';  -- should be 0
update <table> set user_id = '<user-A-uuid>' where user_id <> '<user-A-uuid>'; -- should affect 0 rows
rollback;
```

Record the actual output for the report.

## 4. Fix

Write `supabase/migrations/<timestamp>_rls_guard.sql` with one block per finding. Patterns are in `references/fix-patterns.md`. Defaults:
- Enable RLS on every table in exposed schemas.
- Owner tables: separate select / insert / update / delete policies `to authenticated`, `using ((select auth.uid()) = user_id)`, and the same in `with check` for insert/update.
- Content that is truly public: an explicit `for select to anon, authenticated using (true)` with a comment saying it is public on purpose. Never public writes.
- Move a leaked service key server-side, and tell the user to **rotate it** in the dashboard (removing it from code does not un-leak it).

In `fix` mode: show the migration, ask before applying, apply, then run step 3 again. A fix is done only when the same proof that showed the hole now shows it closed.

## 5. Report

```
RLS Guard — <project> — <date>
Critical: n   High: n   Info/Perf: n

1. [Critical] public.profiles has RLS off
   Proof: curl with anon key returned 3 rows (emails visible)
   Fix: migration block #1 — status: fixed, re-test returned []
...
Not checked: <anything skipped and why>
```

Plain English, one line on why each finding matters. End with what the user must do themselves (rotate keys, check dashboard API settings).
