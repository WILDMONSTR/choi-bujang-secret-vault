# BYTE BACK 방어전 자료실 · 2단계

이 저장소는 2단계 학습용 구성입니다. 화면은 Vercel 서버 함수 `/api/notes`를 통해 Supabase의 `public.learning_notes` 테이블에서 가상 메모 네 건을 읽습니다. 실제 사용자 자료나 실제 비밀값은 이 실습에 넣지 마세요.

## Vercel 환경변수 설정

1. Vercel 대시보드에서 이 프로젝트를 열고 **Settings → Environment Variables**로 이동합니다.
2. `SUPABASE_URL`에 Supabase 프로젝트 URL을 설정합니다.
3. `SUPABASE_SECRET_KEY`에 Supabase의 secret API key를 설정합니다. Supabase 대시보드의 **Project Settings → API Keys**에서 확인할 수 있습니다.
4. 사용할 배포 환경(Production, Preview 등)을 선택해 저장하고, 새 배포를 실행합니다.

환경변수의 **이름과 용도만** 코드에 적습니다. 실제 값은 Vercel의 환경변수 입력란에만 입력하세요. 키를 채팅, GitHub, 브라우저 코드, URL, 응답 본문 또는 로그에 넣지 마세요. 이 키에 `NEXT_PUBLIC_`이나 `VITE_` 같은 브라우저 노출용 접두사를 붙이지 마세요. 실제 키를 나에게 보내지 않아도 됩니다.

## API와 알려진 약점

- `api/notes.js`는 서버에서 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 읽어 `learning_notes` 테이블의 `title`과 `content`만 조회합니다.
- 함수는 정해진 네 제목에 해당하는 가상 메모만 응답하며, 키와 원본 오류는 응답하거나 로그로 남기지 않습니다.
- Supabase secret key는 RLS를 우회할 수 있는 높은 권한의 키이므로 서버 밖으로 유출되면 안 됩니다.
- **현재 알려진 약점:** `/api/notes`는 공개 URL이고 호출자 인증·로그인 확인·요청 제한을 구현하지 않았습니다. 누구나 URL을 직접 열어 네 건의 가상 메모를 읽을 수 있습니다. 이 단계에서는 가상 데이터만 사용하며, 실제 자료를 다루려면 인증·인가·요청 제한을 추가해야 합니다.

## 정적 파일과 배포

- `public/data.json`은 제거했습니다. 빌드 스크립트도 예전 파일이 남아 있으면 지우며 다시 만들지 않습니다. 배포 주소의 `/data.json`은 찾을 수 없음(일반적으로 HTTP 404)이 정상입니다.
- 화면은 `/api/notes`를 호출해 네 카드를 그립니다. 브라우저 코드에는 Supabase URL/secret key 환경변수가 포함되지 않습니다.
- Vercel 빌드는 `aleph.config.json`의 2~12단계를 지원합니다. 비로컬 배포에서는 기존처럼 `public/aleph.json`에 배포 식별 정보를 생성합니다. `--local` 빌드는 해당 배포 식별 파일을 생성하지 않습니다.
- `npm run build -- --local`은 로컬 빌드 확인용이고, 실제 Vercel 배포 완료를 증명하지 않습니다.
- 점검 명령은 `npm run test:r5`와 `npm run test:package`입니다. 실행하지 않은 테스트나 실제 API 요청을 성공했다고 간주하지 마세요.
