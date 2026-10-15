begin;

create extension if not exists pgcrypto with schema extensions;

-- Audit the server-confirmed revocation of a different approved device.
-- History contains identifiers and timestamps only, never cookies or note content.
create table if not exists public.stage12_device_revocation_audit (
  revocation_id uuid primary key default extensions.gen_random_uuid(),
  device_id uuid not null,
  owner_id uuid not null,
  actor_id uuid not null,
  status text not null check (status = 'revoked'),
  created_at timestamptz not null default clock_timestamp()
);

create index if not exists stage12_device_revocation_actor_created_idx
  on public.stage12_device_revocation_audit (actor_id, created_at desc);

alter table public.stage12_device_revocation_audit enable row level security;
revoke all on public.stage12_device_revocation_audit from public, anon, authenticated;
grant select, insert on public.stage12_device_revocation_audit to service_role;

create or replace function public.stage12_revoke_device(
  p_device_id uuid,
  p_owner_id uuid,
  p_actor_id uuid,
  p_current_device_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $function$
declare
  v_device public.app_devices%rowtype;
  v_revocation_id uuid;
  v_now timestamptz := clock_timestamp();
begin
  if p_owner_id is distinct from p_actor_id then
    raise exception 'DEVICE_REVOKE_OWNER_MISMATCH';
  end if;
  if p_device_id is null or p_current_device_id is null
     or p_device_id = p_current_device_id then
    raise exception 'DEVICE_REVOKE_CURRENT_FORBIDDEN';
  end if;

  select * into v_device
  from public.app_devices
  where id = p_device_id and owner_id = p_owner_id
  for update;

  if not found then
    raise exception 'DEVICE_NOT_FOUND';
  end if;
  if v_device.status = 'revoked' then
    raise exception 'DEVICE_ALREADY_REVOKED';
  end if;
  if v_device.status <> 'approved' then
    raise exception 'DEVICE_NOT_APPROVED';
  end if;

  update public.app_devices
  set status = 'revoked'
  where id = p_device_id and owner_id = p_owner_id and status = 'approved';
  if not found then
    raise exception 'DEVICE_STATE_CHANGED';
  end if;

  insert into public.stage12_device_revocation_audit (
    device_id, owner_id, actor_id, status, created_at
  ) values (
    v_device.id, p_owner_id, p_actor_id, 'revoked', v_now
  ) returning revocation_id into v_revocation_id;

  return jsonb_build_object(
    'revoked', true,
    'deviceId', v_device.id,
    'status', 'revoked',
    'revocationId', v_revocation_id,
    'revokedAt', v_now
  );
end;
$function$;

revoke all on function public.stage12_revoke_device(uuid, uuid, uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.stage12_revoke_device(uuid, uuid, uuid, uuid)
  to service_role;

commit;
