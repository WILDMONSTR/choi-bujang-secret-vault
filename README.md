# BYTE BACK 방어전 자료실 · 12단계

이 저장소는 1~11단계의 로그인·로그아웃, 사용자별 가상 메모 소유권, 판정·탐지 연습, 안전한 복원, 설치형 웹앱과 서버 확인형 기기 승인을 보존하는 학습용 구성입니다. 12단계에서는 실제 API·DB 응답을 읽는 탈환 작전실, 승인 기기 회수와 결과 출처 표시를 추가합니다. 실제 운영 정책·실제 사용자 자료·비밀값은 이 실습에 넣지 마세요.


## 11단계: 설치형 웹앱과 서버 확인형 기기 승인

- `public/manifest.webmanifest`, `public/sw.js`, `public/app-icon.svg`가 설치 가능한 웹앱 화면과 앱 셸 오프라인 캐시를 제공합니다. 서비스 워커는 HTML/아이콘/클라이언트 모듈만 캐시하며 `/api/` 응답이나 메모 본문을 캐시하지 않습니다.
- `public/device-client.js`에는 기기 개인키 생성·서명 코드, `localStorage`, `sessionStorage`, `IndexedDB` 사용이 없습니다. 등록은 `POST /api/devices/register`이며 서버가 만든 무작위 기기 세션을 `HttpOnly; Secure; SameSite=Strict` 쿠키로 전달합니다. 쿠키 원문은 JavaScript나 API JSON에 노출하지 않고 DB에는 SHA-256 해시만 저장합니다. 새 기기는 `pending` 상태로만 생성됩니다.
- 화면은 `GET /api/devices/status`의 서버 응답이 `approved`라고 확인된 경우에만 기존 자료실을 엽니다. 로그인 직후나 승인 요청 버튼 클릭만으로 메모를 표시하지 않습니다. 첫 기기는 `POST /api/devices/approve-self`에서 로그인 이메일과 비밀번호를 다시 확인한 뒤 승인하며, 이후에는 이미 승인된 기기에서 `POST /api/devices/approve`로 같은 계정의 대기 기기를 승인할 수 있습니다.
- 보호된 메모 및 공지 API는 로그인 사용자와 `HttpOnly` 기기 세션을 서버에서 확인하고, `app_devices`의 소유자 및 `approved` 상태를 매 요청마다 검사합니다. 승인 전·회수된 기기에서는 메모 목록을 열지 않고, API도 보호 자료를 반환하지 않습니다.
- DB의 `app_devices`와 기존 `app_device_request_nonces` 테이블은 RLS가 켜져 있고 `anon`/`authenticated` 권한이 제거되어 있습니다. `device_cookie_sha256`에는 쿠키 원문이 아닌 SHA-256 해시만 저장합니다. 서버는 기존 `SUPABASE_SECRET_KEY` 환경변수로만 이 테이블에 접근합니다. 비밀값이나 개인키를 저장소에 추가하지 않습니다.

### 11단계 검사

```powershell
npm install
npm run device:test
npm run stage11:test
npm run decider:test
npm run resource-id:test
npm run detect:test
npm run stage10:test
npm run test:r5
npm run test:package
npm run build -- --local
```

`npm install`과 위 검사는 이 변경을 작성한 시점에 원격 실행 환경에서 실제로 실행하지 않았습니다. 실행 후에만 통과 여부를 기록하세요. 기기 등록·승인 및 서명 검증은 배포 환경에서 로그인한 가상 계정으로 추가 확인해야 합니다. `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY`는 Vercel 환경변수로 설정하고 값을 GitHub나 채팅에 보내지 마세요.


## 12단계: 탈환 작전실과 실제 방어 결과

- 승인된 로그인 기기에서만 「탈환 작전실」을 엽니다. 상태 패널은 `/api/stage10/operations-status`가 응답한 현재 기기 등록 상태, 실제 회수 기록, 복구 감사 기록을 읽습니다. DB 조회가 실패하면 실패/조회 불가로 표시하고 성공으로 바꾸지 않습니다.
- 「학생 판정기 검사」는 현재 배포의 `src/decider.mjs`에 고정된 가상 요청 4건을 실제로 전달합니다. 「학생 탐지기 검사」도 `src/detect.mjs`에 121건의 가상 GET 사건을 전달해 결과를 읽습니다. 이는 학생 코드 자기 점검이며 외부 심판 41종 공격 결과가 아닙니다. 탐지기는 회수를 제안할 뿐, 그 검사 자체가 회수 API를 실행하지 않습니다.
- 기기 회수는 현재 승인된 기기가 다른 승인 기기 한 대를 회수하는 작업입니다. 서버가 소유자와 현재 기기를 다시 확인한 뒤 DB 트랜잭션에서 `app_devices.status=revoked`로 바꾸고 `stage12_device_revocation_audit`에 회수 ID·대상·시각을 기록합니다. 현재 기기 자체의 회수와 타 계정 기기 회수는 거부합니다.
- 익명 메모 API 검사 5건은 쿠키·인증 정보를 보내지 않고 실제 배포 API에 요청합니다. 다른 사용자 메모 검사는 시험 계정 A의 UUID를 입력해야 실행되고, 화면에는 메모 본문을 출력하지 않고 HTTP 상태·오류 코드·본문 포함 여부만 표시합니다. 구역 경계 검사는 접근 권한이 없는 테스트 구역 ID를 입력해 실행합니다. 입력이 없거나 버튼을 누르지 않은 검사는 미실행 상태입니다.
- 「41종 공격 방어」는 외부 심판의 시험별 실행 기록을 반환하는 조회 API가 이 저장소에 제공되지 않았습니다. 작전실은 엔진 접수 URL을 결과 API로 가장하지 않으며, 이 화면에서 확인한 로컬/실제 API 점검과 외부 심판의 41종 결과를 분리합니다. 따라서 현재 화면만으로 41종 통과나 마지막 총공세 클리어를 선언하지 않습니다. 최종 클리어는 심판이 12단계 통과와 41종 공격 방어를 모두 확인해야 합니다.
- 출처 표시는 현재 배포의 `/aleph.json`에서 저장소 주소·커밋 SHA·단계·샘플 표식을 읽습니다. 학생 코드의 판정·탐지 출처는 `src/decider.mjs`, `src/detect.mjs`입니다. 제공 엔진의 접수 주소는 `aleph.config.json`의 `judgeIssuer`이며, 접수 URL만으로 엔진 소스나 심판 실행 결과가 공개된다고 가정하지 않습니다.
- 이 단계의 쓰기 API는 이전 단계의 브라우저 서명 키 방식을 되살리지 않습니다. 현재 설계의 서버 검증형 `HttpOnly` 세션 쿠키, 허용된 HTTPS Origin 확인, 등록·승인 기기 검사를 유지하며, 변경 요청에는 유효한 브라우저 Origin도 요구합니다.

### 12단계 검사

```powershell
npm install
npm run stage12:test
npm run device:test
npm run stage11:test
npm run decider:test
npm run detect:test
npm run resource-id:test
npm run stage10:test
npm run test:r5
npm run test:package
npm run build -- --local
```

복구 기록이 0건이면 「복구 완료」가 아니라 「감사 기록 없음」입니다. 회수·복구 결과는 서버에서 돌려받은 상태와 DB 감사 기록을 대조하세요. 로컬 또는 가상 요청 결과는 실제 심판 점수로 보고하지 마세요. `npm run bundle`은 별도 로컬 저장소에서 실제 API 자기 점검을 한 다음 실행하며, `bundle-notes.json`과 `artifacts/submission.json`은 커밋하지 않습니다.

## 5단계: 서버 로그인과 사용자별 메모 소유권

- `public/index.html`에는 Supabase 키와 Supabase JavaScript SDK가 없습니다. 브라우저는 `/api/auth/login`, `/api/auth/session`, `/api/auth/logout` 및 `/api/notes` 서버 경로만 호출합니다. 로그인 세션은 `HttpOnly; Secure; SameSite=Lax` 쿠키로 전달되므로 JavaScript가 access token이나 refresh token을 읽지 않습니다.
- `src/verify-login.mjs`는 수정하지 않았습니다. `api/notes.js`와 `api/notes/[id].js`가 이 검증기를 이용하며, 확인된 Supabase 로그인 사용자의 ID만 권한 판단과 `owner_id` 저장에 사용합니다. 요청 본문이나 쿼리에 있는 `userId`·`role`은 신뢰하지 않습니다.
- `GET /api/notes`는 로그인 사용자에게 속한 메모 배열 `[{id,title,body}]`를 반환합니다. `POST /api/notes`는 `{id?,title,body}`를 받고, ID가 없으면 서버에서 UUID를 만들며 `{id}`를 HTTP 201로 반환합니다. 생성 시 검증된 사용자 ID를 `owner_id`로 저장합니다.
- `GET /api/notes/:id`는 본인 소유의 한 건만 `{id,title,body}`로 반환합니다. 존재하지 않거나 다른 사용자가 소유한 ID는 404 `NOT_FOUND`를 반환해 자료의 존재 여부를 노출하지 않습니다. `PUT /api/notes/:id`와 `DELETE /api/notes/:id`에도 메모 ID와 검증된 `identity.userId`의 `owner_id` 조건이 모두 적용됩니다.
- `aleph.config.json`의 `allowedRoutes`에는 실제 GET·POST·PUT·DELETE 경로를 기록했습니다. `identityProvider`에는 Supabase Auth issuer, JWKS URL과 `authenticated` audience만 기록하며 비밀 키는 넣지 않습니다.

## 소유권 검사와 남은 주의사항

- 비로그인 요청과 토큰 검증 실패는 HTTP 401 `{"error":"UNAUTHORIZED"}`로 거부되며, 메모는 반환하지 않습니다.
- 목록 조회와 단건 GET·PUT·DELETE는 서버가 검증한 사용자 ID로 `owner_id`를 필터링합니다. 다른 사용자가 메모 UUID를 알아도 단건 조회·수정·삭제는 `404 NOT_FOUND`로 거부됩니다. RLS 정책도 방어 심층화 용도로 유지하지만, secret key를 사용하는 서버 API의 소유권 필터를 대체하지는 않습니다.
- `learning_notes.title`은 데이터베이스에서 전역 고유값이므로 다른 계정에 같은 제목이 이미 있으면 API가 HTTP 409 `TITLE_ALREADY_EXISTS`를 반환할 수 있습니다.
- 요청 횟수 제한은 아직 구현하지 않았습니다. Supabase secret key는 RLS를 우회할 수 있는 높은 권한의 키이므로 Vercel의 `SUPABASE_SECRET_KEY` 환경변수에만 보관하세요.

## Vercel 환경변수 설정

1. Vercel 대시보드에서 이 프로젝트를 열고 **Settings → Environment Variables**로 이동합니다.
2. `SUPABASE_URL`에 Supabase 프로젝트 URL을 설정합니다.
3. `SUPABASE_PUBLISHABLE_KEY`에 Supabase의 publishable key(`sb_publishable_...`)를 설정합니다. 브라우저 HTML 코드에는 넣지 않습니다. 이 값은 서버 로그인 API가 Auth 요청을 보낼 때만 읽습니다.
4. `SUPABASE_SECRET_KEY`에 Supabase의 secret API key를 설정합니다. Supabase 대시보드의 **Project Settings → API Keys**에서 확인할 수 있습니다.
5. 사용할 배포 환경(Production, Preview 등)을 선택해 저장하고, 새 배포를 실행합니다.

환경변수의 **이름과 용도만** 코드에 적습니다. 실제 값은 Vercel의 환경변수 입력란에만 입력하세요. 키를 채팅, GitHub, 브라우저 코드, URL, 응답 본문 또는 로그에 넣지 마세요. `SUPABASE_PUBLISHABLE_KEY`는 서버 환경변수로만 설정하고 `NEXT_PUBLIC_`이나 `VITE_` 같은 브라우저 노출용 접두사를 붙이지 마세요. 실제 키를 나에게 보내지 않아도 됩니다.

## 정적 파일과 배포

- `public/data.json`은 제거했습니다. 빌드 스크립트도 예전 파일이 남아 있으면 지우며 다시 만들지 않습니다. 배포 주소의 `/data.json`은 찾을 수 없음(일반적으로 HTTP 404)이 정상입니다.
- 브라우저 소스에는 Supabase 프로젝트 키를 두지 않습니다. 로그인·세션 확인은 `/api/auth/login`, `/api/auth/session`, `/api/auth/logout` 서버 경로를 사용하며, 쿠키는 `HttpOnly; Secure; SameSite=Lax`로 설정합니다. publishable key와 secret key는 모두 서버 환경변수로만 읽습니다.
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
3. `/api/notes`와 `/api/notes/:id` 응답은 정적 파일이 아니므로 정적 파일 검색과 구분하세요. 이 API들은 토큰 검증 후 메모 데이터를 반환할 수 있습니다. 3단계에서는 단건 소유자 검사가 빠져 있었으며, 4단계에서는 서버에서 검증한 사용자 ID의 `owner_id` 조건을 추가했습니다. 실제 배포에 수정이 반영됐는지는 배포 후 별도로 확인하세요.
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

**2단계 당시 공개 API 약점 — 과거 기록**

- 이 기록 작성 당시의 `GET /api/notes`는 로그인이나 호출자 인증 없이 네 건의 가상 메모를 반환했습니다. 이후 3단계에서 이 경로에 토큰 검증을 추가했습니다.
- 이 내용은 3단계 당시의 상태를 설명하는 과거 기록입니다. 4단계 코드에서는 `/api/notes/:id`의 GET·PUT·DELETE에 `owner_id = identity.userId` 조건을 추가했습니다. 과거 배포 URL이나 예전 커밋이 남아 있다면 그 환경의 약점은 별도로 검토해야 합니다.

**과거 노출 상태 — 해결로 간주하지 않음**

이 절차와 현재 `/data.json`의 404만으로는 과거 노출이 해소되었다고 판단할 수 없습니다. 이전에 공개된 Git 커밋이나 과거 Vercel 배포가 남아 있다면 옛 메모 본문이나 정적 파일을 계속 열람할 수 있을 가능성이 있습니다. 이전 커밋의 내용과 이전 배포 URL을 별도로 감사하고 필요한 정리·비활성화를 검증하기 전에는 과거 노출이 해결됐다고 쓰지 마세요.


## 6단계: 등록한 기기만 자료실에 들어옵니다

### 판정 요청에서 사용자와 기기 확인 값 찾기

- 사용자 주체: `subjectId`는 발급자·반·프로젝트와 연결된 가명 주체 ID이며, Supabase 사용자 번호 그 자체가 아닙니다.
- 기기 ID: `deviceId`는 확인된 기기의 16자리 소문자 16진수 ID이며 개인키가 아닙니다.
- 등록 상태: `deviceRegistered`가 기기 등록 여부를 나타냅니다. 이 값은 계약에 따라 반 엔진이 판정 요청에 넣는 값이며, 브라우저가 보낸 임의의 기기 상태를 신뢰해 채우면 안 됩니다.

### 판정 규칙과 확인 순서

1. `docs/DECIDER_REQUEST.md`에서 요청·응답 계약을 먼저 확인합니다. 요청 사용자 주체는 `subjectId`, 기기 등록 여부는 `deviceRegistered`입니다.
2. `src/decider.mjs`의 `RULE_IDS`에 `device_registered`가 있는지 확인합니다. `request.deviceRegistered !== true`이면 `deny`와 `device_not_registered`를 반환합니다. 값이 없거나 `false`여도 거부되며, 등록된 요청만 기존 위험 신호·추가 확인 규칙으로 진행합니다.
3. 프로젝트 루트에서 `npm run decider:test`를 실행합니다. 추가 접속 프로그램을 설치할 필요는 없습니다.
4. 정상 통과 출력은 등록 기기 요청의 `allow · approved`입니다. 미등록 또는 등록 값 누락 테스트는 각각 `deny · device_not_registered`여야 합니다. 기존 복합 이상 요청 및 재확인 테스트 결과도 함께 확인합니다.

예상 출력의 핵심 줄:

```text
통과 · 등록 기기의 정상 요청 · allow · approved
통과 · 미등록 기기의 가상 요청 · deny · device_not_registered
통과 · 기기 등록 값이 없는 가상 요청 · deny · device_not_registered
통과 · 복합 이상 접속 · step_up · step_up_required
통과 · 다시 확인한 복합 이상 접속 · allow · approved
이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.
```

이 시험은 가상 요청으로 로컬 판정 규칙을 확인할 뿐, 운영 심판의 판정이나 실제 릴레이의 접속 차단이 작동했다는 증거가 아닙니다. 배포 화면에서 등록 기기의 기존 로그인·자료실 화면이 열리는지는 해당 기기에서 별도로 확인해 기록하세요. 이번 단계에서 인증서·CA·서명 키·기기 개인키를 새로 만들거나 Git에 넣지 않습니다.


## 7단계: 평소와 다른 접속은 다시 확인합니다

### 제작 1 — 접속 정보의 출처와 입력 검사

- 판정기는 계약에 있는 18개 요청 필드만 허용합니다. 요청에 headers 같은 추가 필드가 붙거나 signals에 정의되지 않은 필드가 들어오면 신뢰하지 않습니다.
- 현재 문서화된 로컬 테스트 신호 출처는 judge_fixture뿐입니다. 실제 경로의 source none, region/network unknown, 누락·형식 오류, 헤더를 출처로 주장하는 값은 정상 접속 정보로 바꾸지 않고 step_up_required로 보냅니다.
- recentEvents를 포함해 행동 정보도 실제 필드 형식으로 검사합니다. 기본 지역·시각·네트워크·행동값을 만들어 채우지 않습니다.
- 이 가상 출처는 로컬 픽스처 표시일 뿐 실제 위치·네트워크 증명이 아닙니다. 운영 엔진이 검증된 출처를 계약으로 제공하기 전에는 실제 접속 신호가 준비됐다고 간주하지 않습니다.

### 제작 2 — 복합 이상 접속 규칙

- unusual_access_context는 비정상 시각(06:00 이전 또는 22:00 이후), first_seen 네트워크, 최근 300초 이내 bulk_read 10건 이상이 모두 결합될 때 추가 확인을 요청합니다.
- 지역 하나만으로는 차단하지 않습니다. 복합 이상 요청은 step_up / step_up_required 및 규칙 ID로 사유를 남깁니다.
- 기존 device_registered 기기 등록 차단과 기존 위험 사건 규칙을 유지합니다.

로컬 가상 요청 시험 (프로젝트 루트에서 실행):

    npm run decider:test
    npm run fixture:7

정상 요청은 allow, 복합 이상 요청은 step_up이어야 합니다. 헤더 추가·불명확한 출처·필수 신호 누락은 정상 요청으로 허용하지 않고 추가 확인으로 보냅니다. 지역만 다른 요청은 이 새 규칙만으로 차단하지 않습니다. 두 명령은 가상 테스트이며 실제 심판 판정이나 실사용 자료 차단 증거가 아닙니다.

### 제작 3 — 재로그인 계약 확인 및 미실행 범위

- docs/DECIDER_REQUEST.md의 현재 요청 계약에는 같은 subjectId의 재로그인 시각을 증명하는 필드나 재로그인 이벤트가 없습니다. stepUp.verified와 stepUp.authAgeSeconds는 추가 인증 상태·경과 시간일 뿐, 그 자체로 같은 계정의 재로그인 시각을 증명하지 않습니다.
- 따라서 이 단계에서는 가상 복합 이상 사건을 시험하고, stepUp 완료 후 가상 요청을 재판정하는 로컬 동작만 확인 대상으로 둡니다. 재로그인 전 실제 자료 접근 차단과 새 로그인 후 실서비스 요청 재판정은 **미실행**입니다.
- 실제 자료 응답이 추가 확인 전 차단되는지는 엔진이 재로그인 계약을 제공하고 그 경로에 접속 차단을 연결한 뒤 별도로 실측해야 합니다. 토큰 원문이나 로그인 비밀값은 기록하지 않습니다.


## 자원 ID 구분과 기존 주소 호환

- 기존 `learning_notes.id`와 `instructor_announcements.id`는 그대로 유지합니다. 데이터 행을 다시 만들거나 기존 UUID를 변경하지 않으며, DB 스키마 변경도 필요하지 않습니다.
- 메모 API 응답에는 기존 `id`와 함께 `resourceType: "memo"`, `resourceId: "memo:<UUID>"`를 반환합니다.
- 강사 공지 API 응답에는 기존 `id`와 함께 `resourceType: "instructor-announcement"`, `resourceId: "instructor-announcement:<UUID>"`를 반환합니다. 두 종류의 UUID가 우연히 같더라도 `resourceId`는 구분됩니다.
- 기존 경로 패턴은 그대로 유지합니다: `/api/notes/:id`, `/api/announcements/:id`. 항목 API는 이전의 UUID만 있는 주소와 유형 접두사가 포함된 자원 ID를 모두 받습니다. 단, 다른 자원 유형의 접두사를 붙인 ID는 거부합니다.
- 메모 카드에는 `자원 ID: memo:<UUID>`를 표시합니다. 내비게이션과 화면 메뉴는 변경하지 않습니다.

## 자원 구역·소유자·강사 권한 방어

- DB의 `resource_zones`와 `resource_zone_memberships`가 구역 및 활성 사용자별 `student` / `instructor` 역할을 관리합니다. 기존 노트는 `personal` 구역에 보존되고, 기존 소유자에게 개인 구역 학생 멤버십이 부여됐습니다.
- `learning_notes.zone_id`로 메모를 구역에 묶습니다. `GET /api/notes?zoneId=...`는 구역 멤버십 확인 후 그 구역에서도 로그인 사용자 자신의 `owner_id`와 일치하는 메모만 반환합니다. 생성·단건 조회·수정·삭제도 구역 권한과 소유자를 다시 확인합니다.
- `instructor_announcements`는 공지를 별도 자원으로 분리합니다. `GET /api/announcements?zoneId=...`는 해당 section 구역 멤버만 읽을 수 있고, 생성·수정·삭제는 활성 강사 멤버십을 요구합니다. 수정·삭제에는 공지 작성자와 로그인 사용자 ID 일치도 필요합니다.
- 판정기의 `resource_scope`는 주체 ID·기기 ID·서비스·HTTP 동작·정확한 경로와 경로 템플릿을 검사합니다. 허용되지 않은 경로는 거부합니다. `instructor_role_required`는 계약에 신뢰할 수 있는 역할 필드가 없으므로 공지 변경을 판정기에서 기본 거부합니다.
- API는 Supabase secret key로 동작하므로 RLS를 우회할 수 있습니다. 따라서 최종 API에서도 사용자 ID·구역 멤버십·소유자·강사 역할을 명시적으로 확인합니다. DB RLS는 추가 방어층으로 유지됩니다.
- 새 section 구역과 강사 멤버십은 자동 생성하지 않습니다. 관리자가 승인된 사용자만 등록하기 전에는 구역 접근과 공지 변경이 거부됩니다. 엔진 계약에 검증된 역할 정보가 추가되기 전까지 판정기 경유 공지 변경은 활성화하지 않습니다.


## 8단계: 자원 범위와 공지 쓰기 기본 거부

- 판정기는 메모 컬렉션 경로 `GET /notes`를 허용하지 않습니다. `GET /api/notes` 별칭도 `aleph.config.json`의 `allowedRoutes`에서 제외했습니다. 다른 사람의 메모를 모아 읽는 경로가 판정 정책을 통과하지 않게 하기 위한 변경입니다.
- 단건 메모 읽기 `GET /notes/:id`는 유지합니다. 메모 한 건의 실제 소유자와 구역 멤버십은 판정기가 아니라 최종 API가 검증합니다. 메모 생성과 단건 수정·삭제의 기존 소유자 검사도 유지합니다.
- 요청 계약에는 신뢰할 수 있는 역할 필드가 없으므로 공지·반 공지·강사 자료에 대한 `POST`, `PUT`, `PATCH`, `DELETE`는 역할 표기와 관계없이 판정기에서 거부합니다. 클라이언트가 보낸 `role` 값으로 허용 여부를 결정하지 않습니다.
- 기존의 미등록 기기 차단, 신호 출처 검증, 위험 사건 및 복합 이상 접속의 추가 확인 규칙은 유지합니다. 자료의 최종 API 인증·소유자·구역 검사는 판정기를 통과해도 별도로 필요합니다.
- 가상 판정 규칙은 `npm run decider:test`, 자원 ID 호환은 `npm run resource-id:test`로 확인합니다. 이 테스트들은 로컬 검증일 뿐 실제 심판 점수나 모든 실서비스 데이터 접근 경로가 안전하다는 증거는 아닙니다.
- `npm run bundle`은 로컬에서 제외 목록에 있는 `bundle-notes.json`을 읽고 실제 배포 URL에 대한 자기 점검을 수행해 `artifacts/submission.json`을 만듭니다. 해당 파일과 산출물은 비밀값과 실자료를 포함하지 않도록 관리하고 저장소에 커밋하지 않습니다.

### 8단계 보완 기록 — 자료 API 권한 재확인

- 8단계 저장점 이후 `src/resource-access.mjs`와 메모·공지 API를 한 번 더 보완했습니다. 토큰으로 검증한 주체를 Supabase Auth 사용자와 재대조하고, 요청 본문이나 화면의 `role` 값은 권한 근거로 사용하지 않습니다.
- 메모는 `owner_id`와 `zone_id`, 공지는 활성 section 멤버십의 저장된 역할과 공지의 `created_by`를 서버에서 다시 검사합니다. 거부 사유는 `UNAUTHORIZED`, `ZONE_ACCESS_DENIED`, `INSTRUCTOR_REQUIRED`, `ANNOUNCEMENT_OWNER_REQUIRED`, `NOT_FOUND`처럼 짧은 코드로 남깁니다.
- 보완 커밋: [Recheck API owner and instructor permissions](https://github.com/WILDMONSTR/choi-bujang-secret-vault/commit/6bb9f9d3c3461faaf10d5ee45161acee3576aad9). 이 변경은 새 단계가 아니라 8단계 보완입니다.

## 9단계: 도플갱어를 찾고 권한을 거둡니다

- `src/detect.mjs`는 `docs/DETECT_EVENTS.md`에 정한 `at`, `method`, `identity.sub` 세 값만 탐지 계약으로 사용합니다. 네트워크나 기기 ID가 없어도 유효한 사건입니다.
- 같은 `identity.sub`의 `GET` 사건이 어느 이동 10분 구간에서든 120건을 초과할 때만 회수 제안을 반환합니다. 정확히 120건은 제안하지 않으며, 서로 다른 사용자의 사건은 합산하지 않습니다.
- 제안 결과는 정확히 `{ action: "propose_revocation", reasonCode: "burst_read", subject: "..." }`이고, 나머지 결과는 정확히 `{ action: "observe" }`입니다.
- 이 탐지기는 제안 결과만 반환하며 실제 회수 API나 권한 변경을 수행하지 않습니다. 탐지 결과가 기존 허용·거부 판정을 대체하지 않습니다.
- 로컬 시험은 `npm run detect:test`입니다. 테스트 통과는 실제 회수나 심판 합격 증거가 아닙니다.

## 10단계: 백업에서 자료실을 되살립니다

### 범위와 사전 준비

- 복원 범위는 별도 시험 정책 테이블의 services.learning_notes 하나뿐입니다. 운영 정책 파일이나 운영 정책 테이블은 수정하지 않습니다. 다른 서비스 규칙은 현재 시험 정책 값으로 유지하고, 기존 감사 이력을 변경하거나 삭제하지 않습니다.
- Supabase SQL Editor에서 supabase/migrations/202610140001_stage10_recovery.sql을 검토한 후 적용하세요. 이 마이그레이션은 복구용 저장 구조와 서버 전용 트랜잭션 함수만 만듭니다. 실제 침해 전 정책 사본이나 메모 백업을 만들어 내거나 추정해서 채우지 않습니다.
- 별도로 보관된 정책 사본과 시험 정책을 신뢰할 수 있는 경로로 stage10_safe_policy_copies 및 stage10_test_policies에 적재해야 합니다. 시험 메모의 비공개 사본은 stage10_memo_backups에 적재합니다. 원본 사본의 검증을 수행한 담당자는 validated, captured_at, validated_at, incident_at, SHA-256을 확인한 뒤 기록해야 합니다.
- Vercel의 서버 환경변수로 STAGE10_TEST_OWNER_B_ID(시험 계정 B의 Supabase 사용자 UUID), STAGE10_SAFE_POLICY_VERSION(안전 사본 버전), STAGE10_SAFE_POLICY_SHA256(정규화한 전체 policy_json의 SHA-256)을 설정하세요. 실제 값, 메모 본문, 토큰, 비밀 키는 README나 Git에 기록하지 마세요.
- 현재 저장소에는 신뢰할 수 있는 실제 정책 사본이나 메모 사본이 포함되어 있지 않습니다. 따라서 별도 준비가 아직 안 됐다면 엔드포인트는 SAFE_POLICY_COPY_UNAVAILABLE 또는 MEMO_BACKUP_UNAVAILABLE 등으로 안전하게 중단해야 합니다. 이 상태에서 복구가 성공했다고 보고하지 마세요.

### 제작 1 — 변경 차이 미리보기

- 서비스: learning_notes 시험 정책.
- 경로: GET /api/stage10/policy-diff.
- 호출자는 로그인한 시험 계정 B여야 합니다. 서버는 환경변수에 고정된 사본 버전과 SHA-256, 저장된 사본의 해시, 검증 상태와 시각을 서로 대조합니다. 검증이 끝나지 않거나 사본이 없으면 중단합니다.
- 응답은 복원할 버전, 안전 사본과 현재 시험 정책의 해시, services.learning_notes 범위, 이전 값과 현재 값의 차이를 보여 줍니다. 변경 범위 밖의 다른 서비스 규칙은 변경 항목으로 반환하거나 복원 대상으로 삼지 않습니다. 민감한 항목명에 해당하는 값은 가립니다. 이 경로는 읽기 전용입니다.
- 차이가 100개 항목에 도달해 응답의 truncated가 true면, 전체 차이를 확인할 수 없으므로 POST 복원을 거부합니다. 전체 변경 범위를 확인하지 않은 상태로 복원하지 마세요.

### 제작 2 — 시험 정책 복원

1. 먼저 GET /api/stage10/policy-diff 결과를 확인합니다. 복원 버전과 변경 범위가 올바르고 canRestore가 true인지 확인하세요.
2. 미리보기 결과의 snapshotId, restoreVersion, snapshotSha256, currentSha256, currentUpdatedAt을 그대로 사용해 POST /api/stage10/policy-restore에 confirm: true를 포함해 요청합니다.
3. 서버는 사본을 다시 검증하고, 미리보기 이후 현재 시험 정책이 바뀌지 않았는지 확인한 뒤 한 트랜잭션에서 services.learning_notes 부분만 복원합니다. 다른 서비스 설정은 유지하고, 과거 감사 행은 유지한 채 별도 복원 감사 행을 추가합니다.
4. 정책 사본이 없거나 지문이 틀리거나 미리보기 뒤 정책이 바뀌었다면 복원은 거부됩니다. 이 기능은 stage10_test_policies만 대상으로 하며 실제 운영 정책은 변경하지 않습니다.

### 제작 3 — 시험 계정 B의 메모 한 건 복원

- 서비스: learning_notes.
- 경로: POST /api/stage10/memo-restore.
- 요청 JSON에는 backupId, noteId, ownerId, contentSha256, confirm: true를 포함합니다. ownerId는 서버에서 검증한 로그인 주체 B와 같아야 합니다.
- 요청에 본문을 직접 실어 보내는 방식이 아닙니다. 서버가 비공개 stage10_memo_backups에서 사본을 읽어 백업 ID, 메모 ID, 소유자 ID, 내용 SHA-256, 검증 여부와 침해 이전 시각을 대조합니다.
- 서버는 지정한 메모 ID 한 건만 삽입하거나 소유자가 같은 기존 행을 복구합니다. 소유자가 다른 기존 메모를 덮어쓰지 않습니다. 다른 메모와 감사 기록은 보존되며 새 감사 행에는 본문 대신 해시와 메타데이터만 기록됩니다. 응답에도 메모 제목·본문은 포함되지 않습니다.
- 성공 응답은 복원 결과의 ID, ownerId, contentSha256, auditId를 돌려줍니다. 이 값을 비공개 사본의 값과 대조하세요. ID·소유자·내용 해시가 일치하지 않으면 성공으로 처리하지 마세요.

### 제작 4 — 복원 뒤 재검사 순서

다음 순서는 실행 지침입니다. 아래 시험은 이 저장점 작성 중 실제로 실행하지 않았으므로 초기 상태는 모두 미실행입니다. 실행한 뒤에만 결과를 갱신하세요.

1. npm install — 미실행
2. npm run stage10:test — 미실행
3. npm run decider:test — 미실행
4. npm run resource-id:test — 미실행
5. npm run detect:test — 미실행
6. npm run fixture:7 — 미실행
7. npm run test:r5 — 미실행
8. npm run test:package — 미실행
9. 배포에서 A로 로그인해 A 소유의 메모 한 건을 조회합니다. 예상 결과는 HTTP 200입니다.
10. B로 로그인해 A 소유 메모 ID를 조회합니다. 예상 결과는 HTTP 404 NOT_FOUND이고 메모 내용이 반환되지 않아야 합니다.
11. B로 로그인해 미리 확인한 백업 한 건만 복원합니다. 응답 ID·소유자 ID·내용 SHA-256을 사본과 대조하고, 다른 메모 및 기존 감사 행이 그대로인지 확인합니다.
12. 1~9단계의 정상·금지 요청을 다시 실행합니다. 미등록 기기, 허용 범위 밖 경로, 공지 쓰기, 출처가 불명확한 신호, 지역 신호만 다른 경우를 이전 단계의 기대값에 맞춰 확인합니다. 실행하지 않은 항목은 미실행으로 유지합니다.

로컬 단위 시험은 실제 Supabase 복원, 배포 API 또는 심판 판정을 증명하지 않습니다. 실제 DB 사본과 환경변수 설정 전에는 복원 성공을 주장할 수 없습니다. 최종 제출 묶음은 준비가 끝난 로컬 저장소에서 npm run bundle로 생성합니다. bundle-notes.json과 artifacts/submission.json은 커밋하지 않습니다.


## 12단계 재제출 안내: 출처와 재현 절차

### 검사 기준과 코드 출처

- 이 안내에서 확인한 읽기 전용 공격 점검 구현의 기준 커밋은 `89e6e219c07393405e6d6452f1cd0f184c02235c`입니다. 이 커밋의 `src/attack-check.mjs`는 공개 HTTPS 주소로 GET만 전송하고, POST·PUT·DELETE 점검은 전송하지 않은 채 `observed: "not_run"`으로 기록합니다. README를 갱신한 문서 커밋은 이 코드 커밋의 후속 커밋이므로, 실제 제출 때에는 `git rev-parse HEAD`로 제출 커밋을 별도로 기록하세요.
- `test/r5.test.mjs`의 회귀 계약은 `f931eff0d5395e52d2ff8d97e8be4f949e57dc6b`에서 읽기 전용 요청 및 `not_run` 동작에 맞췄습니다. 해당 커밋의 [GitHub Actions 검사](https://github.com/WILDMONSTR/choi-bujang-secret-vault/actions/runs/38698856605)는 Ubuntu와 Windows PowerShell 작업 모두 성공했습니다. 화면 파일은 이 보완에서 수정하지 않았습니다.
- **학생 작업(이 저장소):** `src/decider.mjs`의 판정 규칙과 `RULE_IDS`, `src/detect.mjs`의 사건 탐지, `src/attack-check.mjs`의 읽기 전용 자체 점검, `public/index.html` 및 `public/operations-room.js`의 접속 앱·화면, `api/` 및 `src/api-handlers/`의 자료실 API, `supabase/migrations/`의 데이터베이스 변경입니다. 탐지기의 `propose_revocation` 결과는 제안일 뿐 실제 기기 권한을 회수하지 않습니다.
- **제공 엔진(ALEPH SDP 엔진):** `aleph.config.json`의 `judgeIssuer`에 등록된 접수 주소는 ALEPH SDP 엔진에 요청을 제출하기 위한 설정입니다. 엔진 구현 소스는 이 학생 저장소에 포함되어 있지 않습니다. 접수 주소를 실제 시험별 결과 조회 API로 간주하지 말고, 심판 결과를 조회할 수 없으면 미확인으로 기록하세요.
- 학생의 앱·판정·탐지 코드와 제공 엔진의 동작을 같은 출처로 보고하지 마세요. 환경변수 이름은 문서화할 수 있지만, 비밀값·세션 쿠키·토큰·메모 본문은 커밋이나 제출 묶음에 넣지 않습니다.

### 설치

1. Node.js 22.x가 설치되어 있는지 `node --version`으로 확인합니다. 이 프로젝트의 `package.json`과 GitHub Actions는 Node.js 22 계열을 사용합니다.
2. 새 폴더에서 저장소를 가져오고 의존성을 설치합니다.

```powershell
git clone https://github.com/WILDMONSTR/choi-bujang-secret-vault.git
cd choi-bujang-secret-vault
git checkout main
node --version
npm.cmd install
```

Windows PowerShell에서 `npm` 스크립트 실행이 차단되면 `npm.cmd`를 사용합니다. 설치 오류가 나면 원래 오류를 보존하고 무관한 파일이나 잠금 파일을 임의로 수정하지 마세요.

### 실행 및 제출 묶음 생성

1. 먼저 작업 트리와 현재 제출 커밋을 기록합니다.

```powershell
git status --short
git rev-parse HEAD
```

2. 잠금 파일에 맞게 설치한 뒤 프로젝트 검사들을 실행합니다. 각각의 종료 코드와 실제 결과를 기록하고 실행하지 않은 항목은 통과로 표시하지 않습니다.

```powershell
npm.cmd run device:test
npm.cmd run stage11:test
npm.cmd run stage12:test
npm.cmd run decider:test
npm.cmd run resource-id:test
npm.cmd run detect:test
npm.cmd run stage10:test
npm.cmd run test:r5
npm.cmd run test:package
npm.cmd run build -- --local
```

3. 제출 설명 파일 `bundle-notes.json`은 로컬 전용 파일입니다. UTF-8 JSON의 `explanation`에 이번 작업 설명만 적고, 실제 비밀값이나 개인 자료를 넣지 않습니다. `.gitignore`가 이 파일과 `artifacts/`를 제외하는지 확인하고 둘 다 커밋하지 마세요.
4. 작업 트리가 커밋되지 않은 변경 없이 깨끗한 상태인지 확인하고 `npm run bundle`을 실행합니다. Windows PowerShell에서는 다음과 같이 실행합니다.

```powershell
git status --short
npm.cmd run bundle
```

5. 번들러는 현재 커밋의 파일 목록과 규칙 등록을 검사하고 `aleph.config.json`의 공개 HTTPS 주소에 GET 요청을 보내 자체 점검 결과를 만듭니다. 쓰기 요청을 요구하는 점검은 요청하지 않고 `observed: "not_run"`으로 둡니다. 읽기 요청이 실제 HTTP 응답을 받으면 `observed`에는 응답 상태(예: `HTTP 401`)만 기록합니다. 네트워크 실패를 HTTP 상태로 꾸며 쓰지 않습니다.
6. 성공 시 생성된 `artifacts/submission.json`에서 `commit`, `changedFiles`, `attackAttempts`를 확인합니다. 산출물은 해당 실행의 제출 기록이며, 외부 심판의 최종 합격 판정과 같지 않습니다.

### 중지

- `npm run bundle`은 일회성 명령이며 완료되면 종료됩니다. 실행 중 멈춰야 하는 터미널 작업은 `Ctrl+C`로 중단합니다. 이 저장소는 별도 `npm run start` 또는 `npm run dev` 스크립트를 정의하지 않습니다.
- 배포된 앱을 중지하거나 이전 배포로 되돌려야 한다면 Vercel 대시보드의 해당 프로젝트에서 배포 상태와 마지막 정상 배포를 확인한 뒤 운영자가 직접 중지·롤백합니다. 롤백은 앱 코드 배포를 바꿀 뿐 Supabase 데이터나 복구 테이블을 자동으로 되돌리지 않습니다.
- 검사기가 보내는 요청은 읽기 전용 GET뿐입니다. POST·PUT·DELETE를 이용해 상태 변경을 시도하지 마세요.

### 복구

1. 장애나 침해가 의심되면 먼저 추가 변경을 중지합니다. 운영 정책이나 사용자 메모를 임의로 덮어쓰지 않습니다.
2. 자료실의 시험 정책 복구가 필요하면 승인된 로그인과 기기 인증을 정상적으로 거친 시험 계정 B로 `GET /api/stage10/policy-diff`를 먼저 조회합니다. 복구할 사본 버전, SHA-256, 현재 정책 지문과 변경 범위를 확인하고 `canRestore: true`가 아니면 진행하지 않습니다.
3. 신뢰할 수 있는 사전 검증 사본이 없거나 지문·검증 시각이 맞지 않으면 복구를 중단합니다. 추측으로 백업을 만들거나 성공으로 기록하지 않습니다.
4. 미리보기와 현재 상태가 일치하는 경우에만 승인된 절차로 `POST /api/stage10/policy-restore`를 실행하여 `stage10_test_policies`의 `services.learning_notes` 범위만 복원합니다. 메모 한 건은 별도로 검증된 `stage10_memo_backups` 사본이 있을 때만 `POST /api/stage10/memo-restore`로 복구합니다. 이러한 변경 요청은 자체 점검기에서 보내지 않습니다.
5. 응답의 버전·ID·해시와 데이터베이스 감사 기록을 대조하고, 정상 조회 및 타인 소유 메모 접근 거부를 다시 검사합니다. 감사 기록이 없거나 검증을 실행하지 않았으면 각각 `기록 없음` 또는 `미실행`으로 남깁니다. 앱 배포를 롤백했다면 데이터베이스 상태는 별도로 확인합니다.

위 명령과 순서는 재현을 위한 지침입니다. 실제로 실행해 얻은 로그나 HTTP 상태만 결과로 보고하며, 제출 커밋 SHA와 심판이 기록한 요청·결과가 일치하는지 제출 전에 대조하세요.


### 1~11단계 API 증거 통합표 작성 절차

이 표는 각 단계에서 **실제로 실행한 정상 요청과 금지 요청**을 같은 형식으로 모으기 위한 기록 양식입니다. 지금 작성된 문서만으로 1~11단계 요청을 모두 실행한 것은 아니므로, 아래 예시는 양식이며 실제 결과가 아닙니다. 각 개별 API 요청마다 행을 하나씩 추가하고, 실행 전에는 `미실행`으로 둡니다.

| 검사 커밋 SHA | 단계 | 유형 | 실제 요청 (HTTP 메서드·경로) | 기대 결과 | 실제 API 결과 | 요청 ID | 확인 시각 (UTC ISO 8601) | 증거 출처·상태 |
|---|---:|---|---|---|---|---|---|---|
| 제출 시 기록 | 1~11 | 정상 허용 | 미실행 — 실제 요청 경로 기입 | 해당 단계 계약에 정의된 정상 결과 | `not_run` | 응답에 없음 / 미실행 | — | 미실행 |
| 제출 시 기록 | 1~11 | 금지·거부 | 미실행 — 실제 요청 경로 기입 | 해당 단계 계약에 정의된 거부 결과 | `not_run` | 응답에 없음 / 미실행 | — | 미실행 |

**기록 순서**

1. 테스트할 배포의 `/aleph.json` 또는 배포 상세에서 실제 커밋 SHA를 먼저 확인합니다. 이어서 `git rev-parse HEAD`로 제출 커밋을 기록합니다. 서로 다른 커밋의 API 결과를 같은 검사로 합치지 않습니다.
2. 각 단계에서 테스트 계정과 가상 자료만 사용해 정상 허용 요청과 거부되어야 하는 요청을 따로 실행합니다. 브라우저 개발자 도구의 **Network** 탭에서 실제 요청의 메서드·경로·HTTP 상태를 확인하고, 응답에 있는 오류 코드만 필요한 만큼 기록합니다. 메모 제목·본문, 토큰, 쿠키, 개인키는 표나 스크린샷에 넣지 않습니다.
3. 응답 본문이나 헤더에 서버가 발급한 요청 ID가 실제로 있을 때만 그 값을 복사합니다. 없으면 `응답에 없음`이라고 기록합니다. 별도로 만든 검사 번호를 서버 요청 ID인 것처럼 기록하지 않습니다.
4. 확인 시각은 그 요청을 실제로 관측한 시각을 UTC ISO 8601로 기록합니다. 서버가 반환한 시각과 로컬 관측 시각을 혼동하지 않습니다.
5. **실제 응답을 받은 요청에는 실제 HTTP 상태를 기록합니다.** 상태를 받기 전에 네트워크 오류가 났다면 `요청 실패 — HTTP 응답 없음`으로, 전송하지 않았다면 `not_run`으로 기록합니다. 기대 결과에 맞았는지 여부는 별도 판정란이나 증거 출처 설명으로 기록하고, 상태 코드를 임의로 바꾸지 않습니다.
6. 정상·금지 결과가 모두 실측된 행만 검증 완료로 표시합니다. 기대값만 적힌 행, 가상 판정기 결과, 121건 가상 탐지 사건, 외부 심판 결과가 없는 41종 시험을 실제 API 방어 결과로 계산하지 않습니다.
7. 격리된 제출 번들 점검기 `src/attack-check.mjs`는 공개 HTTPS의 GET 요청만 보냅니다. 이 검사기에서는 POST·PUT·DELETE를 보내지 않으며 해당 행은 `observed: "not_run"`입니다. 쓰기 요청이 격리 규칙상 허용되지 않으면 실행하지 않은 채 둡니다. 승인된 테스트 앱에서 별도로 실행할 수 없는 경우에도 추측한 결과를 채우지 않습니다.

### 작전실에서 실제 기록으로 보여 주는 범위

- 판정기 카드의 결과는 학생 코드 `src/decider.mjs`에 전달한 가상 계약 요청의 실제 실행 출력입니다. 응답의 규칙 ID는 `RULE_IDS`와 대조하지만, 이 결과는 실사용자 요청의 판정 이력이 아닙니다.
- 탐지기 카드는 학생 코드 `src/detect.mjs`에 전달한 가상 GET 사건의 실제 출력입니다. `propose_revocation`은 권한 회수가 아니라 회수 제안입니다.
- 기기 수와 회수·복구 기록은 운영실 상태 API가 조회한 실제 DB 행과 조회 시각을 근거로 표시합니다. 정책 미리보기는 복구 버전과 범위의 요약만 보여주고 비밀 정책 값이나 메모 본문을 표시하지 않습니다.
- 현재 DB에는 과거 판정·탐지 이벤트 이력이 저장되지 않고, 설정에 있는 심판 접수 주소도 41종 시험 결과 조회 API가 아닙니다. 그러므로 해당 이력은 **조회 불가/미확인** 상태로 표시되어야 하며, 임의의 수치나 통과 결과로 대체하지 않습니다.

## XDR 보너스 실습: 알려지지 않은 지속성 항목

- `xdr/persistence/decide.mjs`는 가상 파일 무결성, 서비스, 시작 항목, 예약 작업 경보를 분류합니다. 명확한 복합 증거만 차단 후보로 삼고, 단발·불완전한 근거는 알림으로만 분류하며 기준 목록의 정상 이벤트는 기록합니다.
- `npm run xdr:run -- persistence`로 24건의 fixture 분류를 만들고, `node xdr/persistence/respond.mjs`로 차단·알림 로그와 15분 제한 격리 규칙을 가상 실행할 수 있습니다. 이 fixture는 실제 운영 단말 로그가 아닙니다.
- `src/xdr-ztna-gate.mjs`는 기존 brute-force, web-injection, known-CVE 확인에 persistence 확인을 추가합니다. 기존 `src/decider.mjs`는 변경하지 않았으며, XDR 규칙이 일치하지 않으면 기존 정책 판정을 사용합니다.


## XDR 보너스 실습: 권한 상승·계정 세션 거부

- `xdr/privilege/decide.mjs`는 관리자 그룹 변경과 관리자 명령 사용을 판정합니다. 단일 사건만으로 근거가 모자라면 알림만 남기고, `xdr/privilege/respond.mjs`가 동일한 신뢰 계정·출발지의 5분 이내 사건을 상관분석합니다.
- 실행: `npm.cmd run xdr:run -- privilege`, `node xdr/privilege/respond.mjs`, `npm.cmd run privilege:test`.
- 명확한 사건에만 인증된 `subjectId` 기준 15분 ZTNA 거부 규칙을 생성합니다. `src/decider.mjs`는 변경하지 않습니다. 가상 fixture 검사와 로컬 거부 규칙은 실제 Windows 로그 수집이나 IdP 전역 토큰 폐기가 아닙니다.

- 한 번에 분류와 세션 거부 시뮬레이션 실행: `npm.cmd run privilege:run` (실제 단말·IdP 세션을 바꾸지 않는 가상 경보 실행입니다).

- 모듈 판정과 격리 규칙 없이 분류만 재검사: `npm.cmd run privilege:check` (테스트 후 fixture 결과를 만듭니다. 실제 세션을 폐기하지 않습니다).
