# 겨울철방어 — 22단계 최종 커밋 재현·릴리스 기록

> **릴리스 상태: 검증 중(미수료/미운영 인증).** 앱 `on-client/package.json`의 버전은 `0.2.14`이며, 이를 `v1.0` 또는 운영 승인 버전으로 임의 변경하지 않는다. 새 폴더에서 실제 실행한 학생 관측값은 아직 제공되지 않았다. 아래 표의 미실행 항목을 성공으로 바꾸지 않는다.
>
> 이 문서는 **원문 확인과 학생 실행 기록을 분리**한다. 공식 단계 서버의 AI 원문 검토는 학생 PC에서 코드를 실행한 증거가 아니다. 보안 조치의 실제 집행(19단계)은 현재 제공 과제 안내상 미준비이고, 수료 판정과 실제 운영 인증은 별개다.

## 1. 원문·커밋·버전의 식별

| 식별 항목 | 값 | 증거의 종류 |
|---|---|---|
| 학생 Agent | 겨울철방어 | 학생 지정 이름; 제공 실행 로그는 여전히 “케셰브”라고 출력할 수 있음 |
| 저장소 HTTPS | `https://github.com/WILDMONSTR/choi-bujang-secret-vault` | GitHub 저장소 원문 |
| 기준 브랜치 | `main` | GitHub 원문 |
| **이 문서를 작성하기 직전의 원본 코드 기준 커밋** | `86581ccac10ee1e4f6703a5e78b6d178cdf11c65` | GitHub 커밋 확인; **22단계 최종 제출 커밋과 혼동하지 말 것** |
| 21단계 실행 설명서가 추가된 커밋 | `7cfc6774471aef5d4fc532f4b5141dbf47c30021` | GitHub 커밋 확인 |
| **최종 22단계 제출·재현 대상 커밋** | 이 문서를 포함하는 **실제 40자리 커밋**을 GitHub 커밋 화면·`git rev-parse HEAD`·ALEPH 입력란에서 동일하게 대조 | **새 폴더 실행 전에 확인 필요**; 이 파일 자체에 자기 Git SHA를 고정 기입하는 것은 불가능 |
| 앱 버전 | `on-client/package.json` → `0.2.14` | 코드 확인; 릴리스 라벨은 **검증 중** |
| 학생 PC OS·버전 | **미확인** | 학생이 새 PC/폴더의 실제 값을 확인하여 기록 |
| 학생 PC `node --version` | **미확인** | 선언된 수업 기준은 `v24.19.0`, 실행 도구의 허용 범위는 Node 22~24 |
| 브라우저·버전 | **미확인** | 학생이 확인 후 기록 |
| 재현 확인 시각(날짜·시각·시간대) | **미확인** | 실제 명령 실행과 관찰 후 기록 |
| 기존 프로젝트의 Git/파일 상태 | **미확인** | 학생 PC의 기존 원본을 확인해야 함 |

**지원 경계:** 로컬 재현 절차는 Windows PowerShell을 기준으로 소스 확인했다. macOS·Linux에서 제공 Windows 실행 도구가 작동하는지는 확인하지 않았으며 지원 완료라고 주장하지 않는다. 앱을 직접 띄우지 않은 채 브라우저·OS·CLI 실행을 성공으로 기록하지 않는다.

**원문 경계:** Git 최상위 `package.json`은 기존 1~12단계 프로젝트에 속하며 Node.js `22.x`와 외부 npm 패키지를 선언한다. **케세브 실행 대상은 별도 `on-client/package.json`**이다. 여기는 `type: module`, `start = node src/server.mjs`, `demo = node src/server.mjs --demo`, `check = node --check student/extension.mjs`이며 외부 npm 의존성을 선언하지 않는다. `on-client/package-lock.json`은 기준 커밋에서 찾지 못했지만 **저장소 최상위의 `package-lock.json`은 존재**한다. 루트 `npm ci`와 학생 앱 실행 절차를 혼용하지 않는다.

## 2. 현재 소스·설명서 일관성 (원문 확인 ≠ 실행 성공)

| 항목 | 근거 파일 | 원문 대조 결과 | 실제 새 환경 |
|---|---|---|---|
| 기존 설명서 | `on-client/README.md`, `on-client/docs/STUDENT_RUNBOOK.md` | 앱 목적·PowerShell 진입점·버전·오류 안내 존재 | 미확인 |
| 실행 진입점 | `on-client/tools/start-alekov.ps1` → `on-client/src/server.mjs` | 기본 포트 `5189`, 로컬 `127.0.0.1`, `-Port`, `-NoNativeHost`, `-Demo` 옵션 확인 | 미확인 |
| 학생 구현 | `on-client/student/extension.mjs` | `createStudentView()`에서 `renderIdentity`, `renderDecision`, `renderEvents`, `renderStatus`, `renderAiConnection`, `renderExplanation`, `renderAction`, `renderVulnerabilities` 존재 | 미확인 |
| 제공 화면과 API | `on-client/public/index.html`, `on-client/public/app.js`, `on-client/src/server.mjs` | 보호 현황·업무 앱·보안 기록 탭, 요청·표시 연결 코드 존재 | 미확인 |
| 비밀 없는 설정 견본 | `on-client/.env.example` | `ON_PORT`, `ON_ENGINE_ADAPTER`, `ON_AI_MODEL`, `ON_PROJECT_DIRECTORY`, `ON_APPROVED_PUBLIC_PACKAGES` 이름만 확인 | 실제 값·적용 여부 미확인 |
| 엔진·SDP/XDR | `on-client/src/engine.mjs`, `on-client/student/engine-adapter.mjs`, `on-client/src/engine/sdp-host.mjs` | `disconnected`·`demo`·검증된 호스트 연결 구분 | 실제 연결 미확인 |
| AI 게이트 | `on-client/src/ai/service.mjs`, `on-client/src/ai/vault-service.mjs` | 앱 서버 쪽 AI 서비스 호출 구조 존재; 승인은 별도 | 실제 모델 응답 미확인 |
| OSV 패키지 조회 | `on-client/src/vulnerabilities/project-scan.mjs` | 별도 프로젝트 `package-lock.json`과 승인 목록을 읽어 조회, `not_configured`·`not_checked`·`partial`·`complete` 구분 | 실조회 미확인 |
| 조치 집행 | `on-client/src/actions/service.mjs`, `on-client/src/actions/store.mjs`, `on-client/src/server.mjs` | 조치 상태·별도 SQLite 경계가 있으나 기본 실행의 실제 집행 연결은 수용되지 않음 | **실집행 미확인/미완료** |

이 대조는 파일의 존재·설정·함수명 및 호출 경로를 **읽은 결과**이다. GitHub 원문 확인을 Windows 명령 실행, 브라우저 시연, 데이터 복원 또는 공식 과제 통과로 바꿔 표현하지 않는다. `on-client/docs/STUDENT_RUNBOOK.md`의 실행 설명과 모순되는 경우 제공 `package.json`·`tools/start-alekov.ps1`·`src/server.mjs`를 우선하여 실제 실행 위치를 결정한다.

## 3. 원래 폴더를 보존하고 같은 최종 커밋을 별도 폴더로 받는 절차

### 3.1 원본 보존 — 실행 전 **확인 1**

**현재 학생 PC의 실제 Git 최상위 폴더**에서 새 PowerShell 창을 연다. 원본 폴더를 이동·삭제·초기화·덮어쓰기 하지 않는다. Git 저장소인 경우 아래 명령으로 상태만 읽는다.

```powershell
Get-Location
Test-Path -LiteralPath .git
git status --short
git rev-parse HEAD
```

- `Test-Path .git` 결과가 `False`라면 ZIP을 압축 해제한 폴더일 수 있다. 이때 `git status`나 `git rev-parse` 실패를 원본 삭제 또는 작업 미존재로 해석하지 않는다. 기존 파일을 그대로 보존하고 새 복제본은 GitHub 저장소에서 별도로 만든다.
- `git status --short`에 변경 항목이 있으면 어떤 파일인지 먼저 살펴보고 임의로 버리거나 `reset --hard`, `clean -fd` 하지 않는다. 커밋되지 않은 변경은 GitHub에서 `clone`할 때 복제되지 않는다.
- 원본 폴더의 실제 절대경로와 로컬 미커밋 변경 여부는 학생이 직접 기록한다. 사용자 경로에 이름이나 비밀이 포함돼 있으면 제출 문서에는 경로의 공개 가능한 범위만 적는다.

### 3.2 새 폴더 복제 — 제출용 최종 커밋 확정 후

**저장소의 모든 파일을 받는 위치**는 새 빈 폴더다. PowerShell을 임의의 안전한 작업 위치에서 열고 다음을 실행한다. `$targetCommit`에 **22단계 문서 추가 후 실제로 발급된 40자리 커밋**을 입력한다. 원본 기준 커밋 `86581...`을 최종 커밋인 것처럼 사용하지 않는다.

```powershell
$repro = Join-Path $HOME 'winter-defense-stage22-repro'
$targetCommit = '<실제_22단계_제출_커밋_40자리>'
if (Test-Path -LiteralPath $repro) { throw '재현 폴더가 이미 존재합니다. 덮어쓰지 말고 다른 새 폴더를 지정하세요.' }
if ($targetCommit -cnotmatch '^[0-9a-f]{40}$') { throw '제출할 40자리 소문자 Git 커밋을 확인하세요.' }
git clone --no-checkout https://github.com/WILDMONSTR/choi-bujang-secret-vault.git $repro
if ($LASTEXITCODE -ne 0) { throw '복제 실패. 기존 폴더를 수정하지 마세요.' }
git -C $repro checkout --detach $targetCommit
if ($LASTEXITCODE -ne 0) { throw '요청한 커밋으로 이동하지 못했습니다.' }
$actualCommit = git -C $repro rev-parse HEAD
if ($actualCommit -cne $targetCommit) { throw '재현 폴더의 HEAD가 제출 커밋과 다릅니다.' }
git -C $repro status --short
```

확인할 증거: 새 폴더의 `HEAD` 40자리, 제출하려는 커밋 40자리의 일치 여부, 작업 트리 상태. `detached HEAD`는 특정 커밋을 정확히 재현하기 위한 의도적 상태다. 비공개 저장소라면 본인 Git 자격 관리자에서 권한을 확인하되 토큰·비밀번호를 채팅·문서에 기록하지 않는다.

### 3.3 런타임·문법·브라우저·종료·재실행 — 새 폴더에서만

**PowerShell 작업 폴더는 `$repro/on-client`**이다. `on-client`의 외부 npm 의존성은 선언되지 않아 강제 `npm install`을 설치 절차에 추가하지 않는다.

```powershell
Set-Location (Join-Path $repro 'on-client')
node --version
npm run check
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -NoNativeHost -Port 5190
```

- `-NoNativeHost`는 기본 계정 연결 자동 준비를 사용하지 않고 **제공 화면·서버 기동을 먼저 확인**하는 선택 옵션이다. 개인 설정을 새 폴더로 복사하지 않는다. `-Port 5190`은 원본 앱이 `5189`를 쓰더라도 이를 종료하지 않도록 선택한 제공 옵션이다.
- 실행 도구의 예상 메시지는 `케셰브가 켜졌습니다. 브라우저에서 http://127.0.0.1:5190/ 을 여세요.` 와 `서버가 응답한 것만 확인했습니다. AI 연결 상태는 화면에서 따로 확인해 주세요.` 이다. **예상 문구이지 실제 관찰 기록은 아니다.**
- 브라우저에서 `http://127.0.0.1:5190/`를 열어 **「보호 현황」·「업무 앱」·「보안 기록」**과 제공/학생 화면 경계를 확인한다. `disconnected`나 오류는 실제 연결 성공이 아니지만 앱 자체의 표시 동작과 분리해 기록한다.
- 앱 실행 PowerShell 창에서 `Ctrl+C`로 종료한다. 동일 명령으로 **다시 실행**하고, 같은 커밋·주소·화면 상태를 새 시각에 별도로 기록한다. 브라우저 탭을 닫는 것만으로 서버 종료를 판정하지 않는다.
- 외부 SDP/XDR·AI 연결이 필요한 기능은 담당자의 승인과 새 환경 신원 확인을 거쳐 따로 시험한다. 이 재현 문서 작성 과정에서 실제 유료 AI 호출·보안 조치·OSV 외부 조회·계정 승인 요청은 실행하지 않는다.
- 별도의 예제 검사가 필요하다면 제공 `-Demo` 옵션을 쓰고 `mode=demo`와 **예제 자료**로 기록한다. 예제 성공을 연결 성공으로 집계하지 않는다.

`npm run check` 성공은 학생 파일 문법 확인일 뿐이며 로컬 서버·브라우저·API 통과 판정이 아니다. 실제 실행 결과가 나오기 전에는 위 절차를 완료했다고 쓰지 않는다.

## 4. 같은 최종 커밋의 13~21단계 누적 재현 기록

**재현 시험의 공통 제출 대상 커밋:** 3.2의 `$targetCommit`과 실제 `$actualCommit`이 일치한 값. 이 일치를 확인하기 전에는 아래 모든 실행 결과를 **미확인**으로 유지한다. 코드 원문에서 확인한 기능이더라도 새로운 폴더의 관측 사실로 옮기지 않는다.

| 단계 | 확인할 기능(코드상 경로) | 새 폴더 결과 | 실제 확인 시각 | 근거·관찰 결과 | 미확인 이유 / 조건 |
|---|---|---|---|---|---|
| 13 | 「보호 현황」의 현재 사용자·기기·세션; `renderIdentity` | **미확인** | 미확인 | 원문: `student/extension.mjs` | 동일 최종 커밋의 새 폴더에서 아직 관측하지 않음 |
| 14 | 「업무 앱」 판정 `allow/deny/challenge/unknown` 및 근거; `renderDecision` | **미확인** | 미확인 | 원문: `student/extension.mjs` | 실제 원천 판정 미확인 |
| 15 | 「보안 기록」의 `access/xdr` 구분, 필터·상세; `renderEvents` | **미확인** | 미확인 | 원문: `student/extension.mjs` | 실제 기록 조회 및 갱신 미확인 |
| 16 | 기기·세션 상태, 알림·갱신; `renderStatus` | **미확인** | 미확인 | 원문: `student/extension.mjs` | 실제 기기·세션 자료 미확인 |
| 17 | 현재 AI 앱 연결·권한·모델 점검, `renderAiConnection` | **미확인** | 미확인 | 원문: `student/extension.mjs` | 새로운 폴더의 승인·모델 접근 미확인 |
| 18 | 선택 사건의 근거·규칙과 AI 설명; `renderExplanation` | **미확인** | 미확인 | 원문: `student/extension.mjs` | 실제 사건-계정 결속·AI 응답 미확인 |
| 19 | 조치 제안/확인/접수/효과 관측; `renderAction` | **미확인** | 미확인 | 원문: `student/extension.mjs` | **실제 조치 집행 연결 미준비**. 실제 효과 증명 없음 |
| 20 | 정확한 잠금 버전의 승인 패키지 OSV 조회; `renderVulnerabilities` | **미확인** | 미확인 | 원문: `student/extension.mjs`·`src/vulnerabilities/project-scan.mjs` | 승인 패키지·lock 원천·OSV 실응답 미확인 |
| 21 | 학생 실행 설명서·구성도, 새 환경 명령 대조 | **미확인** | 미확인 | 문서 존재: `docs/STUDENT_RUNBOOK.md`(원문 확인) | 다른 사람이 실제로 절차를 따라 실행한 결과 미확인 |

학생이 직접 시험을 마친 항목만 결과를 **재현됨 / 재현 안 됨 / 연결 없음 / 확인 불가** 중 관찰에 맞게 바꾸고, 시각·동일 커밋·화면/명령 결과·오류 코드를 함께 남긴다. 화면이 열렸어도 실제 연결 기능은 `연결 없음`으로 별도 기재할 수 있다. 재현에 성공한 예제는 비고에 `demo / 예제 자료`를 표시하며 **운영 연결 재현 완료로 세지 않는다**. 실험 자체를 하지 않았으면 계속 **미확인**이다. 예전 커밋에서 테스트했던 항목을 이번 단일 커밋의 누적 성공으로 가져오지 않는다.

**공통 실행 관측 표 — 학생이 실제 실행한 뒤에만 채움**

| 절차 | 실제 환경/명령·주소 | 관찰 결과 | 확인 시각·시간대 | 동일 커밋 증거 |
|---|---|---|---|---|
| 원본 파일·Git 기록 보존 | 미확인 | **미확인** | 미확인 | 미확인 |
| 새 복제본 생성 및 HEAD 일치 | 미확인 | **미확인** | 미확인 | 미확인 |
| Node.js 버전 | 미확인 | **미확인** | 미확인 | 미확인 |
| `npm run check` | 명령 원문만 확인 | **미실행** | 미확인 | 미확인 |
| PowerShell 서버 시작 | 명령 원문만 확인 | **미실행** | 미확인 | 미확인 |
| 브라우저 확인 | `http://127.0.0.1:5190/`(예정) | **미실행** | 미확인 | 미확인 |
| PowerShell 종료 및 서버 중지 | `Ctrl+C`(예정) | **미실행** | 미확인 | 미확인 |
| 같은 커밋 재실행 | 동일 명령(예정) | **미실행** | 미확인 | 미확인 |
| 종료·재실행 후 데이터 상태 대조 | 미확인 | **미확인** | 미확인 | 미확인 |

## 5. 데이터 보존·백업·복원 계획과 제한

**원칙:** 소스 커밋, 원격 사용자 데이터, Windows 개인 자격 및 보안 조치 감사 기록을 서로 다른 저장 대상으로 취급한다. 폴더 복제만으로 전체 학생 데이터·기기 승인·AI 자격이 복원됐다고 판단하지 않는다.

| 보존 대상 | 현재 원문 경계 | 보존·백업 계획 | 복원·확인의 제한 |
|---|---|---|---|
| 학생 소스·문서·Git 이력 | Git 추적 파일, `on-client/student/extension.mjs`, `on-client/docs/*` | 원본 폴더 유지; GitHub 원격에 확인된 전체 커밋을 고정해서 clone; 기존 미커밋 변경 유무 별도 확인 | clone에 포함되지 않는 미커밋 변경·Git 제외 파일은 자동 복원 안 됨. 새 폴더의 실제 파일·HEAD 대조 전엔 성공 미확인 |
| 제공 앱 설정 견본 | `on-client/.env.example` | 비밀 없는 **키 이름과 기본 예시만** Git에서 다시 받음 | 설정 견본은 실제 서비스 연결 자격이 아니며 자동 적용을 증명하지 않음 |
| 원격 사용자 메모·접속/XDR 기록 | 저장소 상위 기존 서비스의 Supabase/API 및 SDP 원천; 학생 앱은 연결 경계로 조회 | 기존 원천 데이터를 임의 삭제·변경하지 않음. 실제 백업/내보내기는 자료 소유자·운영자가 승인한 공식 수단과 보존 정책에 따라 별도 시행 | Git clone은 원격 DB·XDR 데이터를 백업/복원하지 않음. 원천 조회 전후의 본인 데이터 범위·건수 등을 운영 권한 아래 대조해야 복원 검증 가능 |
| 계정·AI 개인 설정과 자격 보관소 | `tools/start-alekov.ps1`가 프로젝트 상위 경로에서 계산한 키로 Windows 사용자 폴더 바깥쪽의 별도 경로를 준비; `native.json`·registry·vault 등 | 기존 개인 보관소·권한을 그대로 보존하고 새 폴더로 파일을 임의 복사하지 않음. 별도 폴더의 자격 연결·승인은 현재 사용자와 담당자의 정상 절차로 다시 검증 | 새 경로는 프로젝트 경계가 달라 기존 연결이 자동 승계되지 않음. 수동 파일 복사·ACL 변경·임의 자격 복구 금지 |
| SDP 개인 설정·인증서 | `src/engine/sdp-host-config.mjs`와 제공 `docs/SDP_HOST_CONNECTION.md` | 프로젝트 밖에 보관; 운영자가 제공한 실제 설정과 현재 권한을 개별 확인 | Git·ZIP·화면·이 문서에 비밀을 기록하지 않음. 잘못된 경로 또는 계정이면 연결 미확인으로 유지 |
| 조치 요청·감사 기록 | `src/actions/store.mjs`의 별도 SQLite `databasePath`; `src/actions/action-startup-config.mjs`가 설정 경계 검증 | 실집행을 수행하지 않고 기존 외부 DB를 임의 변경·복사하지 않음. 복구 필요 시 운영자가 승인한 DB 보존·정합성 검증과 독립 백업 절차 필요 | 같은 커밋을 clone해도 기존 외부 SQLite 감사 기록이 생기지 않음. 임의 DB 재생성·감사 내역 조작·효과 확인 주장 금지 |
| OSV 조회 대상 프로젝트 | `src/vulnerabilities/project-scan.mjs`의 `ON_PROJECT_DIRECTORY` 및 공개 승인 목록 | 읽기 전용 원천 잠금 파일·실제 설치 버전·해시를 기존 프로젝트에 보존 | 앱 소스 clone은 별도 설치 프로젝트의 패키지와 그 설치 증거를 복제하지 않음. 미조회/실패를 `none_found`로 바꾸지 않음 |

**백업 확인 순서:** (1) 원본 폴더 및 미커밋 변경 목록 확인 → (2) 제출 커밋의 원격 보존·새 clone 해시 대조 → (3) 개인·원격 데이터의 위치와 별도 관리 주체 확인(비밀 내용은 조회·복사하지 않음) → (4) 승인된 경우에만 운영 원천의 백업/복구 방법과 관측 가능한 데이터 범위를 확인 → (5) 재실행 뒤 원래 범위의 기록·상태가 동일한지 비교. **백업 수행/실제 복원 시험은 현재 모두 미확인**이다.

`.gitignore`은 `.env`, `.env.*`, `node_modules/`, `artifacts/` 및 생성된 일부 규칙 파일을 Git에서 제외한다. 이런 파일과 실행 환경의 별도 자격을 “GitHub ZIP 하나로 모두 복원”할 수 있다고 쓰지 않는다. 오류가 났을 때 원본 폴더·보관소·감사 DB를 지우거나 초기화하지 않는다.

## 6. 실패·변경·릴리스 결정 원칙

| 상황 | 다음 조치 | 기록 상태 |
|---|---|---|
| 새 폴더가 이미 존재 | 덮어쓰지 말고 다른 새 경로를 사용 | 재현 미실행 |
| Git 원본이 ZIP이고 `.git` 없음 | 기존 ZIP 원본 보존, 새 폴더는 GitHub에서 `clone` | Git 기록 확인 불가와 파일 보존 구분 |
| 새 폴더의 HEAD가 제출 커밋과 다름 | 새 결과를 제출 근거로 합치지 않고 커밋을 다시 고정 | 커밋 불일치 |
| `node --version` 불일치·`npm run check` 실패 | 환경/오류 확인, 제공 코드 임의 수정 금지 | 미재현·원인 기록 |
| 원본 서버가 포트 `5189` 사용 | 제공 `-Port 5190` 사용, 기존 프로세스는 유지 | 환경 변경 근거 기록 |
| API `ENGINE_NOT_CONNECTED`, `disconnected` | 현재 호스트 연결 상태 확인; 운영 연결 성공 주장 금지 | 연결 없음 |
| 권한 준비 중, `unknown`, 계약 오류 | 정확한 오류와 다시 확인할 순서만 기록 | 확인 불가 |
| `mode=demo` 화면만 성공 | 예제 표시의 재현으로만 기록 | demo / 예제 자료 |
| 19단계 실제 집행 경로 미준비 | 실제 집행 금지; 효과 미확인 유지 | 미완료 |
| 실행 문제로 학생 문서·학생 코드를 고침 | 기존 변경 보존, **새 커밋 발급**, 그 커밋의 새 복제본에서 13~21 전부 재확인 | 이전 커밋 관측과 합산 금지 |

**버전 결정:** 현재는 **`0.2.14` 기반 ‘검증 중’**으로만 기록한다. 19단계 실제 집행, 새 환경에서 동일 최종 소스의 누적 재현, 공식 단계 수용이 해결되지 않은 동안 `v1.0`·운영 인증·전체 완료를 표시하지 않는다. 22단계 원문 AI 검토 통과가 추후 확인되더라도 이는 해당 과제의 수료 판정이며 실제 운영 보안 인증이나 실제 데이터 복원 성공을 보증하지 않는다.

## 7. 단계 제출 전 학생 확인 (본 과제 범위)

1. 원본을 보존하고 새 폴더에서 **최종 커밋을 일치**시킨다. 그 커밋으로만 표를 채운다.
2. 학생 문서·코드와 재현 표를 같은 Git 커밋에 저장한다. 제출하는 40자리 커밋은 GitHub 화면 또는 `git rev-parse HEAD` 결과와 맞춘다. 코드를 추가로 변경했다면 다시 커밋하고 새 커밋으로 재현한다.
3. 21·22단계는 워크벤치의 13~20단계용 「포털 제출 준비」가 아니라 **ALEPH 단계 화면에 저장소 주소와 40자리 커밋을 직접 입력**한다. 비공개 저장소를 공개로 바꿀 필요가 없다.
4. 비공개 원문은 같은 단계의 **「비공개 저장소 원문 준비 방법」**에 있는 도구를 프로젝트 **밖에서** 준비하고, 실제 안내에 표시된 `student-source-cli.mjs` 명령에서 `--commit`을 제출할 **40자리 커밋**으로 지정한다. 구체적인 압축 파일·도구 경로는 실제 받은 안내와 대조한 뒤에만 사용한다. 도구는 원문을 묶을 뿐 학생 앱을 실행하지 않는다.
5. 생성된 JSON을 같은 단계의 **「비공개 저장소 원문 묶음」**에서 선택하고 저장소·커밋·단계를 재확인한 후 직접 제출한다. **원문 전달 완료와 AI 검토 통과는 다르며**, 원문만 실패하면 기존 접수를 유지해 「원문만 다시 보내기」를 사용한다.

**이 문서 작성 시 남은 미확인:** 원본 PC 보존 확인, 개인 PC 운영체제·Node·브라우저 버전, 새 clone, 동일 최종 HEAD, 학생 화면, 실제 로그인/SDP/XDR/AI/OSV, 실제 조치 효과, 종료·재실행, 데이터 복원, 공식 22단계 판정. 이 중 어떤 항목도 이 문서 작성 자체로 성공하지 않는다.


## 8. AI 격리 실행 환경에서 직접 관측한 재현 증거 (학생 PC 검증과 별도)

**관측일:** 2026-10-28. **실행 원문 커밋:** `040ff787b9f212c20d9e681fa2ab7844041bc1cb`. **증거 종류:** Vercel 격리 샌드박스의 실제 Git 복제, Node.js 명령, HTTP GET 응답, 프로세스 종료·재실행, 모의 DOM 단위 실행. **환경:** Linux amd64 / Node.js `v24.22.1` / npm `11.19.1`, 앱 버전 `0.2.14`. 사용자의 Windows PC를 원격 제어하거나 Windows PowerShell 도구를 실행한 것은 아니다.

| 검사·관측 | 실측 결과 | 근거와 범위 |
|---|---|---|
| Git 원문·보존 | `git rev-parse HEAD` = 상기 40자리, `git status --porcelain` 출력 없음; 문서·학생 코드·서버 경로 존재 | 새로 생성된 별도 샌드박스의 Git 작업 트리. 사용자 원본 PC 폴더 보존 여부는 미확인 |
| Node 문법 | `npm run check` 종료 코드 0; `node --check`로 `src/server.mjs`·`public/app.js`·`public/vulnerabilities-view.mjs`·`student/extension.mjs` 확인 | 실제 Node 24 실행. 기능 통과나 Windows 실행과는 다름 |
| 실제 서버 시작 | `ON_PORT=5190 node src/server.mjs` 실행, `케셰브 연결 확인: http://127.0.0.1:5190` 출력 | Linux 직접 실행. `tools/start-alekov.ps1` 사용 결과가 아님 |
| 브라우저 자료 HTTP | `GET /` = 200 HTML, `GET /app.js` = 200, `GET /student/extension.mjs` = 200, `GET /vulnerabilities-view.mjs` = 200 | 실제 HTTP GET. 실제 브라우저 렌더링은 미확인 |
| 로컬 진단·원천 미연결 | `GET /api/diagnostics` = HTTP 200 / `mode=disconnected`. `GET /api/me`·`/api/apps`·`/api/events`·`/api/devices`·`/api/sessions` = HTTP 503 / `ENGINE_NOT_CONNECTED` | 실제 HTTP 응답. 원천 접속·XDR 성공 아님 |
| 승인 패키지 미설정 | `GET /api/vulnerabilities` = HTTP 200 / `data.status=not_configured` / `PROJECT_NOT_CONFIGURED` | 실제 HTTP 응답. OSV 조회 성공이나 `none_found`가 아님 |
| 동일 커밋 서버 종료·재실행 | 동일 프로세스 모드로 2회 독립 기동. HTTP 상태 일치, 종료 후 포트 연결 거절(`PORT_CLOSED`) | **실제 시작/종료/재실행 확인**, Linux에서만 |
| 예제 모드 | 별도 `node src/server.mjs --demo` 실행. `GET /api/me` = 200, `GET /api/apps` = 200/3건, `GET /api/events` = 200/1건, `meta.mode=demo` | 실제 HTTP에서 **예제 데이터**만 확인. 운영 연결 성공과 분리 |
| 학생 확장 동작 | 실제 `student/extension.mjs`를 import, 모의 `document.createElement`로 렌더러 함수 8종 검사. 신원·판정·XDR 기록·오류·AI 연결·AI 설명 오류·조치 불명·OSV 상태/이전 표 제거 등 **12개 테스트 통과, 실패 0건** | 입력 fixture + 모의 DOM, **Chrome/실제 API UI 시연 아님** |
| 검사 후 오염 여부 | `git rev-parse HEAD` 계속 상기 커밋, `git status --porcelain` 출력 없음 | 테스트 스크립트는 Git 추적 작업 폴더 밖에 임시 작성. 기존 코드 변경 없음 |

**해석:** 이 표는 서버 실행과 제공 엔드포인트의 **미연결 상태 복구 전 경계**를 실제로 관측한 결과다. 13~21단계 운영 시스템 연동, Windows 네이티브 자격, 사용자의 원본 데이터 보존, 브라우저 실제 DOM·접근성, 실제 유료 AI 추론, OSV 실조회, 19단계 실집행과 효과, ALEPH 공식 판정은 **미확인 또는 미완료**다.

**커밋 정합성 주의:** 위 관측은 이 문단을 문서에 추가하기 **직전**의 `040ff787b9f212c20d9e681fa2ab7844041bc1cb`에서 수행했다. 이 기록을 저장한 뒤 새 문서 커밋이 생기므로, **최종 제출할 새 40자리 커밋**도 별도 복제·HEAD 일치 및 같은 기초 검사를 다시 수행해야 한다. 이전 관측을 새로운 커밋에서 직접 실행한 결과로 바꿔 적지 않는다. 이 변경은 학생 문서만 추가하며 런타임 소스는 바꾸지 않는다.
