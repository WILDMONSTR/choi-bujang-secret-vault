begin;

create extension if not exists pgcrypto with schema extensions;

-- Separate test-policy storage; no operational policy table is modified.
create table if not exists public.stage10_test_policies (
  policy_key text primary key check (policy_key = 'learning_notes'),
  version text not null,
  policy_json jsonb not null check (jsonb_typeof(policy_json) = 'object'),
  updated_at timestamptz not null default clock_timestamp()
);

-- Backup rows must come from a separately validated source; this migration adds no fake copy.
create table if not exists public.stage10_safe_policy_copies (
  snapshot_id uuid primary key default gen_random_uuid(),
  policy_key text not null check (policy_key = 'learning_notes'),
  version text not null,
  policy_json jsonb not null check (jsonb_typeof(policy_json) = 'object'),
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  validated boolean not null default false,
  captured_at timestamptz not null,
  validated_at timestamptz not null,
  incident_at timestamptz not null,
  unique (policy_key, version),
  check (captured_at < incident_at),
  check (validated_at < incident_at)
);

-- Private virtual memo backups. Content never leaves the server in an API response.
create table if not exists public.stage10_memo_backups (
  backup_id uuid primary key default gen_random_uuid(),
  note_id uuid not null,
  owner_id uuid not null,
  zone_id text not null check (zone_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  title text not null check (length(btrim(title)) > 0 and length(title) <= 200),
  content text not null check (length(btrim(content)) > 0 and length(content) <= 20000),
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  validated boolean not null default false,
  captured_at timestamptz not null,
  validated_at timestamptz not null,
  incident_at timestamptz not null,
  check (captured_at < incident_at),
  check (validated_at < incident_at)
);

-- Append-only metadata: no note body, token, or authentication secret is stored in audit rows.
create table if not exists public.stage10_restore_audit (
  audit_id uuid primary key default gen_random_uuid(),
  action text not null check (action in ('test_policy_restore', 'virtual_memo_restore')),
  actor_id uuid not null,
  resource_kind text not null,
  resource_key text,
  resource_id uuid,
  owner_id uuid,
  backup_id uuid,
  backup_version text,
  before_sha256 text,
  after_sha256 text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default clock_timestamp()
);

alter table public.stage10_test_policies enable row level security;
alter table public.stage10_safe_policy_copies enable row level security;
alter table public.stage10_memo_backups enable row level security;
alter table public.stage10_restore_audit enable row level security;

revoke all on public.stage10_test_policies from anon, authenticated;
revoke all on public.stage10_safe_policy_copies from anon, authenticated;
revoke all on public.stage10_memo_backups from anon, authenticated;
revoke all on public.stage10_restore_audit from anon, authenticated;
grant select on public.stage10_test_policies to service_role;
grant select on public.stage10_safe_policy_copies to service_role;
grant select on public.stage10_memo_backups to service_role;
grant select on public.stage10_restore_audit to service_role;

create or replace function public.stage10_restore_test_policy(
  p_snapshot_id uuid,
  p_expected_version text,
  p_expected_sha256 text,
  p_expected_updated_at timestamptz,
  p_target_service_policy jsonb,
  p_actor_id uuid,
  p_before_sha256 text,
  p_after_sha256 text
) returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $function$
declare
  v_copy public.stage10_safe_policy_copies%rowtype;
  v_current public.stage10_test_policies%rowtype;
  v_audit_id uuid;
begin
  select * into v_copy
  from public.stage10_safe_policy_copies
  where snapshot_id = p_snapshot_id
  for share;

  if not found
     or v_copy.policy_key <> 'learning_notes'
     or v_copy.version is distinct from p_expected_version
     or v_copy.sha256 is distinct from p_expected_sha256
     or v_copy.validated is distinct from true
     or v_copy.captured_at >= v_copy.incident_at
     or v_copy.validated_at >= v_copy.incident_at
     or v_copy.incident_at > clock_timestamp()
     or (v_copy.policy_json #> '{services,learning_notes}') is distinct from p_target_service_policy then
    raise exception 'SAFE_POLICY_COPY_INVALID';
  end if;

  select * into v_current
  from public.stage10_test_policies
  where policy_key = 'learning_notes'
  for update;
  if not found then
    raise exception 'TEST_POLICY_UNAVAILABLE';
  end if;
  if v_current.updated_at is distinct from p_expected_updated_at then
    raise exception 'POLICY_CHANGED_SINCE_PREVIEW';
  end if;

  update public.stage10_test_policies
  set policy_json = jsonb_set(v_current.policy_json,
        '{services,learning_notes}', p_target_service_policy, true),
      version = v_copy.version,
      updated_at = clock_timestamp()
  where policy_key = 'learning_notes'
  returning * into v_current;

  insert into public.stage10_restore_audit (
    action, actor_id, resource_kind, resource_key, backup_id, backup_version,
    before_sha256, after_sha256, details
  ) values (
    'test_policy_restore', p_actor_id, 'test_policy', 'learning_notes',
    v_copy.snapshot_id, v_copy.version, p_before_sha256, p_after_sha256,
    jsonb_build_object('scope', 'services.learning_notes', 'testOnly', true)
  ) returning audit_id into v_audit_id;

  return jsonb_build_object(
    'auditId', v_audit_id,
    'version', v_current.version,
    'updatedAt', v_current.updated_at
  );
end;
$function$;

create or replace function public.stage10_restore_virtual_memo(
  p_backup_id uuid,
  p_note_id uuid,
  p_owner_id uuid,
  p_zone_id text,
  p_title text,
  p_content text,
  p_expected_content_sha256 text,
  p_actor_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $function$
declare
  v_backup public.stage10_memo_backups%rowtype;
  v_existing_owner uuid;
  v_before_content text;
  v_before_hash text;
  v_audit_id uuid;
begin
  if p_actor_id is distinct from p_owner_id then
    raise exception 'MEMO_OWNER_MISMATCH';
  end if;

  select * into v_backup
  from public.stage10_memo_backups
  where backup_id = p_backup_id
  for share;

  if not found
     or v_backup.note_id is distinct from p_note_id
     or v_backup.owner_id is distinct from p_owner_id
     or v_backup.zone_id is distinct from p_zone_id
     or v_backup.title is distinct from p_title
     or v_backup.content is distinct from p_content
     or v_backup.content_sha256 is distinct from p_expected_content_sha256
     or encode(extensions.digest(convert_to(v_backup.content, 'UTF8'), 'sha256'), 'hex')
          is distinct from v_backup.content_sha256
     or v_backup.validated is distinct from true
     or v_backup.captured_at >= v_backup.incident_at
     or v_backup.validated_at >= v_backup.incident_at
     or v_backup.incident_at > clock_timestamp() then
    raise exception 'MEMO_BACKUP_INVALID';
  end if;

  select owner_id, content into v_existing_owner, v_before_content
  from public.learning_notes
  where id = p_note_id
  for update;

  if found then
    if v_existing_owner is distinct from p_owner_id then
      raise exception 'MEMO_OWNER_MISMATCH';
    end if;
    v_before_hash := encode(extensions.digest(convert_to(v_before_content, 'UTF8'), 'sha256'), 'hex');
    update public.learning_notes
    set title = p_title, content = p_content, zone_id = p_zone_id
    where id = p_note_id and owner_id = p_owner_id;
    if not found then
      raise exception 'MEMO_OWNER_MISMATCH';
    end if;
  else
    v_before_hash := null;
    insert into public.learning_notes (id, owner_id, zone_id, title, content)
    values (p_note_id, p_owner_id, p_zone_id, p_title, p_content);
  end if;

  insert into public.stage10_restore_audit (
    action, actor_id, resource_kind, resource_id, owner_id, backup_id,
    before_sha256, after_sha256, details
  ) values (
    'virtual_memo_restore', p_actor_id, 'virtual_memo', p_note_id, p_owner_id,
    v_backup.backup_id, v_before_hash, v_backup.content_sha256,
    jsonb_build_object('zoneId', p_zone_id, 'testAccountOnly', true)
  ) returning audit_id into v_audit_id;

  return jsonb_build_object(
    'auditId', v_audit_id,
    'id', p_note_id,
    'ownerId', p_owner_id,
    'contentSha256', v_backup.content_sha256
  );
end;
$function$;

revoke all on function public.stage10_restore_test_policy(uuid, text, text, timestamptz, jsonb, uuid, text, text)
  from public, anon, authenticated;
revoke all on function public.stage10_restore_virtual_memo(uuid, uuid, uuid, text, text, text, text, uuid)
  from public, anon, authenticated;
grant execute on function public.stage10_restore_test_policy(uuid, text, text, timestamptz, jsonb, uuid, text, text)
  to service_role;
grant execute on function public.stage10_restore_virtual_memo(uuid, uuid, uuid, text, text, text, text, uuid)
  to service_role;

commit;
