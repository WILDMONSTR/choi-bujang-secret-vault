-- Stage 11: server-only registry for approved device public keys and replay nonces.
-- No private keys or session tokens are stored in the database.
begin;

create table if not exists public.app_devices (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  public_jwk jsonb not null
    check (jsonb_typeof(public_jwk) = 'object'
      and public_jwk->>'kty' = 'EC'
      and public_jwk->>'crv' = 'P-256'
      and not (public_jwk ? 'd')),
  public_key_sha256 text not null
    check (public_key_sha256 ~ '^[0-9a-f]{64}$'),
  label text not null default '이 기기'
    check (length(btrim(label)) between 1 and 80),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'revoked')),
  created_at timestamptz not null default clock_timestamp(),
  approved_at timestamptz,
  approved_by uuid references auth.users(id) on delete set null,
  last_seen_at timestamptz,
  unique (owner_id, public_key_sha256)
);

create index if not exists app_devices_owner_status_created_idx
  on public.app_devices (owner_id, status, created_at desc);

create table if not exists public.app_device_request_nonces (
  device_id uuid not null references public.app_devices(id) on delete cascade,
  nonce text not null check (nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
  signed_at timestamptz not null,
  expires_at timestamptz not null,
  primary key (device_id, nonce),
  check (expires_at > signed_at)
);

create index if not exists app_device_request_nonces_expiry_idx
  on public.app_device_request_nonces (expires_at);

alter table public.app_devices enable row level security;
alter table public.app_device_request_nonces enable row level security;

revoke all on table public.app_devices from public, anon, authenticated;
revoke all on table public.app_device_request_nonces from public, anon, authenticated;
grant select, insert, update, delete on table public.app_devices to service_role;
grant select, insert, update, delete on table public.app_device_request_nonces to service_role;

commit;
