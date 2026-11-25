# Fix patterns

Copy, rename, and keep one block per finding in the migration, each with a comment naming the finding.

## Owner-only table (most common)

```sql
alter table public.notes enable row level security;

create policy "notes: owner reads"   on public.notes for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "notes: owner inserts" on public.notes for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "notes: owner updates" on public.notes for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
create policy "notes: owner deletes" on public.notes for delete to authenticated
  using ((select auth.uid()) = user_id);

create index if not exists notes_user_id_idx on public.notes (user_id);
```

Make `user_id` default to the caller so the client cannot forge it:
```sql
alter table public.notes alter column user_id set default auth.uid();
```

## Public read, owner write (blog posts, public profiles)

```sql
-- Public on purpose: published posts are visible to everyone.
create policy "posts: anyone reads published" on public.posts for select to anon, authenticated
  using (published = true);
-- plus the owner insert/update/delete policies above
```

Do not expose private columns (email, phone) on a public table: move them to a separate owner-only table, or serve the public part through a `security_invoker` view.

## Team / tenant data

```sql
create policy "projects: members read" on public.projects for select to authenticated
  using (exists (
    select 1 from public.memberships m
    where m.project_id = projects.id and m.user_id = (select auth.uid())
  ));
```
Index `memberships (user_id, project_id)`. Make sure `memberships` has its own RLS so users cannot add themselves.

## Roles (admin)

Do not read roles from `user_metadata` (users can edit it). Use `app_metadata` (set only server-side):
```sql
using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin')
```
or a `user_roles` table that only the service role can write.

## Views

```sql
alter view public.my_view set (security_invoker = true);  -- Postgres 15+
```

## SECURITY DEFINER functions

```sql
alter function public.do_thing(uuid) set search_path = '';
revoke execute on function public.do_thing(uuid) from anon, public;
-- or move it: create schema if not exists private; alter function public.do_thing(uuid) set schema private;
```
Inside, check `auth.uid()` yourself: the function skips RLS.

## Storage: per-user folders

```sql
create policy "avatars: owner manages own folder" on storage.objects for all to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text)
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
```
Set the bucket to private unless its files are meant for everyone.

## Firebase

```
match /users/{userId}/{document=**} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}
match /posts/{postId} {
  allow read: if resource.data.published == true;
  allow create: if request.auth != null && request.resource.data.authorId == request.auth.uid;
  allow update, delete: if request.auth != null && resource.data.authorId == request.auth.uid;
}
```
Test with the Firebase emulator's rules tests, not in production.
