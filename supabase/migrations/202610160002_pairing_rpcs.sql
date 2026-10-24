-- One-time, ten-minute invite flow for pairing exactly two anonymous devices.
-- Apply after 202610160001_labchat.sql. The invite code is a 256-bit bearer
-- secret; only its SHA-256 digest is stored in Postgres.

alter table public.messages
  add column if not exists cipher_version smallint not null default 1;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.messages'::regclass
      and conname = 'messages_cipher_version_check'
  ) then
    alter table public.messages
      add constraint messages_cipher_version_check check (cipher_version = 1);
  end if;
end;
$$;

create or replace function public.create_private_invite(
  p_device_public_key bytea
)
returns table (conversation_id uuid, invite_code text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_conversation_id uuid;
  raw_invite_code text;
  public_key_fingerprint text;
begin
  if (select auth.uid()) is null then
    raise exception 'Authentication required';
  end if;
  if p_device_public_key is null or octet_length(p_device_public_key) <> 32 then
    raise exception 'Invalid X25519 public key';
  end if;

  raw_invite_code := encode(extensions.gen_random_bytes(32), 'hex');
  public_key_fingerprint := encode(
    extensions.digest(p_device_public_key, 'sha256'), 'hex'
  );

  insert into public.conversations (invite_hash, invite_expires_at)
  values (
    extensions.digest(convert_to(raw_invite_code, 'UTF8'), 'sha256'),
    now() + interval '10 minutes'
  )
  returning id into new_conversation_id;

  insert into public.conversation_members (
    conversation_id, user_id, device_public_key, key_fingerprint
  ) values (
    new_conversation_id, (select auth.uid()), p_device_public_key,
    public_key_fingerprint
  );

  return query select new_conversation_id, raw_invite_code;
end;
$$;

create or replace function public.join_private_invite(
  p_conversation_id uuid,
  p_invite_code text,
  p_device_public_key bytea
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  invite_record public.conversations%rowtype;
  public_key_fingerprint text;
  member_count integer;
begin
  if (select auth.uid()) is null then
    raise exception 'Authentication required';
  end if;
  if p_device_public_key is null or octet_length(p_device_public_key) <> 32 then
    raise exception 'Invalid X25519 public key';
  end if;

  select * into invite_record
  from public.conversations
  where id = p_conversation_id
  for update;

  if not found then
    raise exception 'Invite not found';
  end if;

  -- Safe to retry a completed join after a lost network response.
  if public.is_conversation_member(p_conversation_id) then
    return p_conversation_id;
  end if;

  if invite_record.invite_hash is null
     or invite_record.invite_used_at is not null
     or invite_record.invite_expires_at <= now()
     or p_invite_code is null
     or invite_record.invite_hash <> extensions.digest(
       convert_to(p_invite_code, 'UTF8'), 'sha256'
     ) then
    raise exception 'Invite is invalid, expired, or already used';
  end if;

  select count(*) into member_count
  from public.conversation_members
  where conversation_id = p_conversation_id;
  if member_count >= 2 then
    raise exception 'Conversation is full';
  end if;

  public_key_fingerprint := encode(
    extensions.digest(p_device_public_key, 'sha256'), 'hex'
  );
  insert into public.conversation_members (
    conversation_id, user_id, device_public_key, key_fingerprint
  ) values (
    p_conversation_id, (select auth.uid()), p_device_public_key,
    public_key_fingerprint
  );

  update public.conversations
  set invite_hash = null, invite_used_at = now()
  where id = p_conversation_id;

  return p_conversation_id;
end;
$$;

revoke all on function public.create_private_invite(bytea) from public, anon;
revoke all on function public.join_private_invite(uuid, text, bytea) from public, anon;
grant execute on function public.create_private_invite(bytea) to authenticated;
grant execute on function public.join_private_invite(uuid, text, bytea) to authenticated;

-- Enable Postgres Changes for the encrypted message rows, if not already added.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime'
         and schemaname = 'public' and tablename = 'messages'
     ) then
    alter publication supabase_realtime add table public.messages;
  end if;
end;
$$;
