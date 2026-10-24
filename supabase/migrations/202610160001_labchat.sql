-- LabChat v1 schema. Requires Supabase Anonymous Sign-ins to be enabled.
-- Anonymous sign-in creates an invisible per-installation identity; there is no
-- email/password screen. Never put a service-role key in the mobile app.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  invite_hash bytea,
  invite_expires_at timestamptz,
  invite_used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  device_public_key bytea not null,
  key_fingerprint text not null,
  joined_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  cipher_version smallint not null default 1 check (cipher_version = 1),
  ciphertext bytea not null,
  nonce bytea not null,
  auth_tag bytea not null,
  created_at timestamptz not null default now()
);

create index if not exists messages_conversation_created_idx
  on public.messages (conversation_id, created_at desc);

alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;

-- SECURITY DEFINER avoids recursive RLS evaluation when checking the
-- conversation_members table from its own policy. Keep the search path empty.
create or replace function public.is_conversation_member(target_conversation uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.conversation_members m
    where m.conversation_id = target_conversation and m.user_id = (select auth.uid())
  );
$$;
revoke all on function public.is_conversation_member(uuid) from public, anon;
grant execute on function public.is_conversation_member(uuid) to authenticated;

create policy "members can read their conversations"
  on public.conversations for select to authenticated
  using (public.is_conversation_member(id));

create policy "members can read members in their conversations"
  on public.conversation_members for select to authenticated
  using (public.is_conversation_member(conversation_id));

create policy "members can read encrypted messages"
  on public.messages for select to authenticated
  using (public.is_conversation_member(conversation_id));

create policy "members can send encrypted messages"
  on public.messages for insert to authenticated
  with check (
    sender_id = (select auth.uid()) and public.is_conversation_member(conversation_id)
  );

-- Invite codes are random bearer secrets, held only by the two devices. Store
-- SHA-256(secret), set a short expiry, and mark the invite consumed at join.
-- Pairing RPCs are added by 202610160002_pairing_rpcs.sql. Do not grant direct
-- client INSERT/UPDATE on conversations or conversation_members.

revoke all on public.conversations, public.conversation_members, public.messages from anon;
grant select on public.conversations, public.conversation_members, public.messages to authenticated;
grant insert on public.messages to authenticated;
