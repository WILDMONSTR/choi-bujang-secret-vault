-- BYTE BACK 2단계: 기존 실습용 가상 메모를 학습용 Supabase 테이블로 옮깁니다.
-- owner_id는 나중에 UUID를 저장할 nullable 칸입니다. auth.users 외래키는 만들지 않습니다.
-- anon 및 authenticated 역할에는 테이블 권한을 주지 않으며, RLS를 활성화하고 정책을 만들지 않습니다.

create table if not exists public.learning_notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid null,
  title text not null unique,
  content text not null,
  created_at timestamptz not null default now()
);

alter table public.learning_notes enable row level security;

revoke all privileges on table public.learning_notes from PUBLIC, anon, authenticated;

insert into public.learning_notes (owner_id, title, content)
values
  (null, '과제', '실습용 가상 과제 기록'),
  (null, '포트폴리오', '실습용 가상 포트폴리오 기록'),
  (null, '아침 리추얼', '실습용 가상 리추얼 기록'),
  (null, '훈련 행정 자료', '실습용 가상 행정 기록')
on conflict (title) do update
set owner_id = excluded.owner_id,
    content = excluded.content;

-- 실행 후 확인 1: owner_id가 nullable UUID인지 확인합니다.
-- 결과: owner_id | uuid | YES
select column_name, data_type, is_nullable
from information_schema.columns
where table_schema = 'public'
  and table_name = 'learning_notes'
  and column_name = 'owner_id';

-- 실행 후 확인 2: RLS가 켜져 있는지 확인합니다.
-- 결과: relrowsecurity = true
select relrowsecurity
from pg_class
where oid = 'public.learning_notes'::regclass;

-- 실행 후 확인 3: auth.users 외래키가 없어야 하므로 결과 행이 없어야 합니다.
select conname
from pg_constraint
where conrelid = 'public.learning_notes'::regclass
  and contype = 'f';

-- 실행 후 확인 4: anon/authenticated에 SELECT 권한이 없어야 합니다.
-- 결과: 두 역할 모두 SELECT 행이 없음
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('anon', 'authenticated')
  and privilege_type = 'SELECT';
