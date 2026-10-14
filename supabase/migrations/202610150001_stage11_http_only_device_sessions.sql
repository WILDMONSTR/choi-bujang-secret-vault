-- Replace app-managed browser signing keys with server-checked HttpOnly device sessions.
-- Existing device rows remain for audit/history; new registrations use a token hash only.
begin;

alter table public.app_devices
  alter column public_jwk drop not null,
  alter column public_key_sha256 drop not null;

alter table public.app_devices
  add column if not exists device_cookie_sha256 text
    check (device_cookie_sha256 is null or device_cookie_sha256 ~ '^[0-9a-f]{64}$');

create unique index if not exists app_devices_device_cookie_sha256_uidx
  on public.app_devices (device_cookie_sha256)
  where device_cookie_sha256 is not null;

alter table public.app_devices enable row level security;
revoke all on table public.app_devices from public, anon, authenticated;
grant select, insert, update, delete on table public.app_devices to service_role;

commit;
