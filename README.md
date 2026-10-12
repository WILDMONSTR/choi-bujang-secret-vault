# BYTE BACK 방어전 자료실 · 3단계

이 저장소는 3단계 학습용 구성입니다. Supabase Auth 이메일·비밀번호 로그인과 로그아웃을 제공하며, 로그인한 사용자가 Vercel API를 통해 자신의 가상 메모 목록을 보고 추가·수정·삭제할 수 있습니다. 실제 사용자 자료나 실제 비밀값은 이 실습에 넣지 마세요.

## 3단계: 로그인과 메모 CRUD

- `public/index.html`은 Supabase 공식 JavaScript SDK `@supabase/supabase-js` 2.117.2의 `signInWithPassword`, `signOut`, `onAuthStateChange`를 사용합니다. 로그인 토큰은 API 요청의 `Authorization: Bearer ...` 헤더로 전송합니다.
- `src/verify-login.mjs`는 수정하지 않았습니다. `api/notes.js`와 `api/notes/[id].js`가 이 검증기를 이용하며, 확인된 Supabase 로그인 사용자의 ID만 권한 판단과 `owner_id` 저장에 사용합니다. 요청 본문이나 쿼리에 있는 `userId`·`role`은 신뢰하지 않습니다.
- `GET /api/notes`는 로그인 사용자에게 속한 메모 배열 `[{id,title,body}]`를 반환합니다. `POST /api/notes`는 `{id?,title,body}`를 받고, ID가 없으면 서버에서 UUID를 만들며 `{id}`를 HTTP 201로 반환합니다. 생성 시 검증된 사용자 ID를 `owner_id`로 저장합니다.
- `GET /api/notes/:id`는 한 건을 `{id,title,body}`로 반환하고, 없거나 삭제된 ID는 404를 반환합니다. `PUT /api/notes/:id`는 `{title,body}`를 수정하고, `DELETE /api/notes/:id`는 삭제 후 204를 반환합니다.
- `aleph.config.json`의 `allowedRoutes`에는 실제 GET·POST·PUT·DELETE 경로를 기록했습니다. `identityProvider`에는 Supabase Auth issuer, JWKS URL과 `authenticated` audience만 기록하며 비밀 키는 넣지 않습니다.

## 알려진 약점 — 소유자 검사는 4단계에서 추가

- 비로그인 요청과 토큰 검증 실패는 HTTP 401 `{"error":"UNAUTHORIZED"}`로 거부되며, 메모는 반환하지 않습니다.
- **3단계에서 일부러 남긴 약점:** 목록 조회는 `owner_id`로 로그인 사용자의 메모만 필터링하지만, 단건 GET·PUT·DELETE에는 아직 `owner_id` 조건이 없습니다. 다른 로그인 사용자가 메모 UUID를 알고 있으면 해당 메모를 읽거나 수정하거나 삭제할 수 있습니다. 이것은 4단계에서 고칠 예정이며, 현재는 가상 데이터만 사용하세요.
- `learning_notes.title`은 데이터베이스에서 전역 고유값이므로 다른 계정에 같은 제목이 이미 있으면 API가 HTTP 409 `TITLE_ALREADY_EXISTS`를 반환할 수 있습니다.
- 요청 횟수 제한은 아직 구현하지 않았습니다. Supabase secret key는 RLS를 우회할 수 있는 높은 권한의 키이므로 Vercel의 `SUPABASE_SECRET_KEY` 환경변수에만 보관하세요.

## Vercel 환경변수 설정

1. Vercel 대시보드에서 이 프로젝트를 열고 **Settings → Environment Variables**로 이동합니다.
2. `SUPABASE_URL`에 Supabase 프로젝트 URL을 설정합니다.
3. `SUPABASE_SECRET_KEY`에 Supabase의 secret API key를 설정합니다. Supabase 대시보드의 **Project Settings → API Keys**에서 확인할 수 있습니다.
4. 사용할 배포 환경(Production, Preview 등)을 선택해 저장하고, 새 배포를 실행합니다.

환경변수의 **이름과 용도만** 코드에 적습니다. 실제 값은 Vercel의 환경변수 입력란에만 입력하세요. 키를 채팅, GitHub, 브라우저 코드, URL, 응답 본문 또는 로그에 넣지 마세요. 이 키에 `NEXT_PUBLIC_`이나 `VITE_` 같은 브라우저 노출용 접두사를 붙이지 마세요. 실제 키를 나에게 보내지 않아도 됩니다.

## 정적 파일과 배포

- `public/data.json`은 제거했습니다. 빌드 스크립트도 예전 파일이 남아 있으면 지우며 다시 만들지 않습니다. 배포 주소의 `/data.json`은 찾을 수 없음(일반적으로 HTTP 404)이 정상입니다.
- 브라우저에는 공개 프로젝트 URL과 publishable key만 사용하며, 서버 전용 secret key는 포함하지 않습니다.
- Vercel 빌드는 `aleph.config.json`의 2~12단계를 지원합니다. 비로컬 배포에서는 `public/aleph.json`에 배포 식별 정보를 생성합니다. `--local` 빌드는 해당 배포 식별 파일을 생성하지 않습니다.
- `npm run build -- --local`은 로컬 빌드 확인용이고, 실제 Vercel 배포 완료를 증명하지 않습니다.
- 점검 명령은 `npm run test:r5`와 `npm run test:package`입니다. 실행하지 않은 테스트나 실제 API 요청을 성공했다고 간주하지 마세요.

## 가상 메모 문장 노출 점검 절차와 기록

아래 네 문장은 Supabase에 저장한 가상 메모의 본문입니다. 이 항목은 **현재 배포의 정적 파일**과 **GitHub 최신 브랜치의 실행 파일**에 이 문장들이 하드코딩되어 있는지 확인하기 위한 검색어입니다.

- `실습용 가상 과제 기록`
- `실습용 가상 포트폴리오 기록`
- `실습용 가상 리추얼 기록`
- `실습용 가상 행정 기록`

### 1. 현재 배포의 정적 파일 검색

1. 2단계 당시 배포 주소 [자료실](https://choi-bujang-secret-vault-eosin-zeta.vercel.app/)을 열고 브라우저 개발자 도구(F12)의 **Network** 탭으로 이동합니다.
2. 캐시를 끄고 페이지를 새로고침합니다. 문서·JavaScript·CSS 등 **정적 리소스**의 응답(Response)을 확인하고, 위 네 문장을 각각 정확히 검색합니다. 문서 응답은 `view-source:https://choi-bujang-secret-vault-hol8fmyub-rryk1212-4030.vercel.app/`로 별도로 확인할 수도 있습니다.
3. `/api/notes`와 `/api/notes/:id` 응답은 정적 파일이 아니므로 정적 파일 검색과 구분하세요. 이 API들은 토큰 검증 후 메모 데이터를 반환할 수 있고, 3단계에서는 단건 GET·PUT·DELETE의 소유자 검사가 아직 없습니다.
4. `/data.json`을 열어 404 또는 410인지 확인합니다. `/aleph.json`은 배포 식별 정보를 확인하는 용도입니다. `/data.json`의 404는 그 경로가 없다는 증거일 뿐, 모든 정적 리소스를 검색했다는 증거는 아닙니다.
5. 각 문장별로 결과를 기록합니다. 정적 리소스에서 발견되면 URL, 리소스 이름, 일치한 문장을 기록하고, 노출이 해결됐다고 결론 내리지 마세요.

### 2. GitHub 최신 실행 파일 검색

저장소를 로컬에 복제한 환경에서 PowerShell 또는 터미널로 다음 명령을 실행합니다. 먼저 원격 브랜치를 갱신한 다음, 현재 `origin/main`의 브라우저·서버 실행 파일과 빌드 스크립트만 검색합니다.

```sh
git fetch origin
git grep -n -F -e "실습용 가상 과제 기록" -e "실습용 가상 포트폴리오 기록" -e "실습용 가상 리추얼 기록" -e "실습용 가상 행정 기록" origin/main -- public api scripts src
```

- 일치 행이 출력되면 파일 경로와 줄 번호를 기록하고 해당 문장이 실행 파일에 포함된 이유를 확인합니다.
- 출력이 없고 종료 코드가 1이면 지정한 경로에서 정확한 문장을 찾지 못한 것입니다. 이는 해당 실행 파일 경로의 검색 결과일 뿐, 과거 커밋이나 이전 배포까지 검색한 결과는 아닙니다.
- 이 README에는 검색어 자체가 적혀 있으므로 위 명령은 README를 포함하지 않는 실행 파일 경로만 대상으로 합니다. README의 검색어 일치 결과를 메모 본문 유출로 세지 마세요.

GitHub 웹에서는 저장소의 `main` 브랜치에서 **Code** 검색을 사용해도 됩니다. 단, 검색 인덱스나 검색 범위에 따라 결과가 달라질 수 있으므로 중요한 판정은 최신 브랜치의 파일 내용을 직접 확인하거나 위 명령으로 재검증합니다.

### 2단계 잔존 점검 기록 — 2026-10-12

**GitHub 최신 실행 파일 검색**

- 확인한 애플리케이션 코드 기준 커밋: `76883f91c2ccd498921cca7ffead3499d88c2b77`.
- 네 본문 문구에 대한 GitHub 코드 검색에서는 일치 결과가 반환되지 않았습니다. 최신 `public/index.html`과 `api/notes.js`를 직접 확인했을 때도 네 본문 문구가 리터럴 문자열로 포함되어 있지 않았습니다. `api/notes.js`는 본문을 소스에 고정하는 대신 데이터베이스에서 `title, content`를 조회합니다.
- README만 변경한 이후에도 위의 `git grep` 명령을 최신 `origin/main` 기준으로 다시 실행해 결과를 기록하세요.

**현재 배포 확인**

- 사용자가 확인한 `/data.json` 응답: **404**. 이 경로의 정적 파일은 현재 배포에서 찾을 수 없다는 결과입니다.
- 사용자가 확인한 `/aleph.json`: `step: 2`, 저장소 주소, 커밋, 배포 주소 및 `STEP2_PROTECTED` 표식이 예상값과 일치했습니다.
- 현재 배포의 모든 정적 리소스에서 네 본문 문구를 각각 검색한 전체 결과는 이 기록 작성 시점에 독립적으로 검증하지 못했습니다. 따라서 **정적 파일 전체 검색을 통과했다고 기록하지 않습니다.** 위 절차를 실행한 뒤 문장별 결과를 여기에 추가하세요.

**공개 API 약점 — 별도 기록**

- `GET /api/notes`에는 아직 로그인이나 호출자 인증이 없습니다. URL을 아는 누구나 호출해 네 건의 가상 메모 본문을 읽을 수 있습니다. 본문이 정적 파일에서 검색되지 않더라도 이 API를 통한 공개 접근은 남아 있는 약점입니다.
- 이 검사는 정적 파일의 현재 상태를 확인하는 절차이지 접근 제어를 입증하는 검사가 아닙니다. 실제 자료를 사용하기 전에 인증·인가 및 요청 제한을 구현해야 합니다.

**과거 노출 상태 — 해결로 간주하지 않음**

이 절차와 현재 `/data.json`의 404만으로는 과거 노출이 해소되었다고 판단할 수 없습니다. 이전에 공개된 Git 커밋이나 과거 Vercel 배포가 남아 있다면 옛 메모 본문이나 정적 파일을 계속 열람할 수 있을 가능성이 있습니다. 이전 커밋의 내용과 이전 배포 URL을 별도로 감사하고 필요한 정리·비활성화를 검증하기 전에는 과거 노출이 해결됐다고 쓰지 마세요.
