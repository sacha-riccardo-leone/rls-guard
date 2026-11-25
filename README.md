# rls-guard

**A Claude Code skill that finds where your Supabase or Firebase app leaks data, proves it, and writes the fix.**

The public (anon) key of a Supabase or Firebase app ships in every visitor's browser. Whatever your rules allow for that key, anyone on the internet can do. AI-built apps often ship with RLS turned off, policies like `using (true)`, a `service_role` key in the frontend, or functions that let any user act as any other.

`rls-guard` checks for all of that, shows you proof of each hole, writes a migration you review, and then shows the same proof failing once the hole is closed.

## Install

```
/plugin marketplace add sacha-riccardo-leone/rls-guard
/plugin install rls-guard@rls-guard
```

Or copy `skills/rls-guard/` into `~/.claude/skills/`.

## Use

| Command | What it does |
|---|---|
| `/rls-guard` or `/rls-guard audit` | Read-only audit with a ranked report. Changes nothing. |
| `/rls-guard fix` | Audit, then write `supabase/migrations/<ts>_rls_guard.sql`. Applies it only after you approve, then re-runs the proofs. |
| `/rls-guard test` | Re-run the proofs only. |

It also triggers on things like *"is my Supabase secure?"*, *"can users see each other's data?"*, or *"audit my Firebase rules"*.

## What it checks

- Tables in exposed schemas with RLS off
- Always-true policies for `anon` / `authenticated`
- `with check` weaker than `using` (users moving rows to other users or tenants)
- Sensitive columns users can update on their own rows (`role`, `plan`, `tenant_id`, tokens…). RLS limits which rows a user can touch, not which columns.
- Policies that trust `user_metadata`, which users can edit themselves
- Views that skip RLS (no `security_invoker`)
- `SECURITY DEFINER` functions callable through `/rpc/`, and whether ones that take a user id check it against `auth.uid()`
- Public storage buckets and storage policies with no owner check
- `service_role` keys in client code, and secrets in git history that are **still live** (compared by hash, never printed)
- Firebase: `if true` rules, test-mode rules that expire, and `auth != null` checks with no ownership check

Works best with the [Supabase MCP server](https://supabase.com/docs/guides/getting-started/mcp) connected. Without it, it reads your migrations and uses `psql` or the SQL in `references/`.

## Safety

- Only audit projects you own.
- On a production database with real users, it only reads: it proves holes with requests using the public key and by reading permissions and policies.
- Everywhere else, write tests run inside `begin; … rollback;`.
- It never prints secrets. It tells you where a key is, not what it is.

## License

MIT
