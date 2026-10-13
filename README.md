# BYTE BACK 방어전 자료실 · 9단계

이 저장소는 1~6단계에서 만든 Supabase Auth 로그인·로그아웃, 사용자별 가상 메모 소유권과 등록 기기 판정 규칙을 보존하고, 7단계 「평소와 다른 접속은 다시 확인합니다」의 접속 정보 출처 검사와 복합 이상 접속의 가상 판정 시험을 다루는 학습용 구성입니다. 로그인한 사용자는 본인 소유의 가상 메모만 조회·추가·수정·삭제할 수 있으며, 목록과 단건 API는 서버에서 검증한 사용자 ID를 기준으로 소유자를 확인합니다. 실제 사용자 자료나 실제 비밀값은 이 실습에 넣지 마세요.

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

- \`src/detect.mjs\`는 운영 반 엔진이 확인한 \`at\`, \`method\`, \`identity.sub\`, \`deviceId\`, \`network\`만 받습니다. \`region\`은 선택적 문맥 정보로 기록할 수 있지만 탐지 조건으로 쓰지 않습니다. 확인되지 않은 값이나 알 수 없는 필드는 거부합니다.
- 회수 제안은 동일한 주체와 동일한 가상 기기에서 **평소와 다른 네트워크(\`first_seen\`)의 GET 조회가 10분 안에 120건을 넘을 때만** 나옵니다. 결과는 별도 탐지 객체 \`{ action: "propose_revocation", reasonCode: "unusual_network_burst_read", target: { kind: "virtual_device", deviceId: "..." } }\`입니다.
- 평소 네트워크의 다량 조회, 새 네트워크에서의 120건 이하 조회, 지역 정보 차이만으로는 \`observe\`를 유지합니다. 서로 다른 사용자·기기·네트워크 상태의 조회는 합산하지 않으며, 여러 대상이 동시에 조건을 만족해도 가장 먼저 임계값을 넘은 한 대만 제안합니다.
- 이 탐지 결과는 기존 접속 허용·거부 판정 응답과 분리되어 있습니다. 이 모듈은 제안만 반환하며, 실제 회수 API를 호출하거나 기기 권한을 바꾸지 않습니다. 실제 회수와 첫 의심 요청부터의 경과 시간은 운영 심판이 별도 가상 사건으로 확인해야 합니다.
- 로컬 가상 시험은 \`npm run detect:test\`로 실행합니다. 복합 신호만 제안하고 정상·지역 단독 사건은 \`observe\`를 유지하는지, 정상 기기가 대상에서 제외되는지, 잘못된 필드가 거부되는지 확인합니다. 테스트 통과는 실제 회수나 심판 합격 증거가 아닙니다.
