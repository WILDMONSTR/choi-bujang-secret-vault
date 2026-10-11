# BYTE BACK 방어전 자료실 · 2단계

이 저장소는 2단계 학습용 구성입니다. 공개 정적 경로에는 메모 본문을 배포하지 않습니다. 학습용 가상 메모 네 건은 `supabase/learning-notes.sql`을 통해 Supabase의 `public.learning_notes` 테이블로 옮기도록 준비했습니다. 실제 사용자 데이터나 실제 키는 넣지 마세요.

## 1. Supabase SQL 실행

1. Supabase 프로젝트를 열고 **SQL Editor**로 이동합니다.
2. 저장소의 [`supabase/learning-notes.sql`](supabase/learning-notes.sql) 파일 내용을 붙여 넣습니다.
3. **Run**을 눌러 실행합니다. 이 SQL은 `owner_id uuid null` 칸을 만들지만 `auth.users` 외래키는 만들지 않습니다.
4. 테이블에 RLS를 켜고 `anon` 및 `authenticated`의 테이블 권한을 회수합니다. 접근 정책은 추가하지 않습니다.

## 2. SQL 실행 결과 확인

SQL 파일 맨 아래의 확인 쿼리를 실행하거나 아래 결과를 확인하세요.

- `owner_id`: `data_type = uuid`, `is_nullable = YES`
- RLS: `relrowsecurity = true`
- 외래키 조회: 결과 행 없음
- `anon` 및 `authenticated`의 `SELECT` 권한 조회: 결과 행 없음

테이블 소유자나 관리자 역할의 SQL Editor에서 행을 볼 수 있다는 사실은 익명 사용자에게 읽기 권한이 있다는 뜻이 아닙니다. 브라우저에 서비스 역할 키를 넣지 마세요.

## 3. 공개 파일과 빌드

- `data.json` 및 `public/data.json`은 `STEP2_PROTECTED` 표시와 빈 `notes` 배열만 포함합니다.
- `public/index.html`은 메모 API를 호출하지 않으며 메모 본문을 렌더링하지 않습니다.
- `npm run build -- --local`은 로컬에서 공개 정적 파일을 생성합니다. 실제 배포 확인은 Vercel에서 별도로 수행해야 합니다.
- `npm run test:r5`와 `npm run test:package`는 이 저장소에 정의된 자동 테스트입니다. 테스트나 배포를 실행하지 않았다면 완료로 보고하지 마세요.

2단계 변경은 공개 정적 파일에서 메모를 제거하는 것입니다. 이 작업만으로 Supabase 테이블에 대한 브라우저 로그인이나 사용자별 조회 API가 구현되는 것은 아닙니다.
