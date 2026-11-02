# 겨울철방어(케셰브) 처음 실행하기 — 일반 사용자 안내

작성일: 2026-11-02
대상: GitHub 저장소 `WILDMONSTR/choi-bujang-secret-vault`의 22단계 프로젝트, Windows PowerShell 일반 권한
원칙: 기존 `student/` 파일·이미 제출한 자료를 보존한다. 관리자 권한, 보안 설정 변경, 공격 시험, 앱 포장은 사용하지 않는다.

> **먼저 알아둘 점:** 앱 창이 열렸다는 것, 이 PC 상태를 읽었다는 것, ALEPH 계정이 연결됐다는 것, 앱 AI가 연결됐다는 것, SDP 서버가 연결됐다는 것은 **모두 서로 다른 결과**다. 하나가 성공해도 다른 연결이 성공한 것은 아니다. 예시 화면은 실측이 아니다.

## 1. 겨울철방어에서 무엇을 보나

- **보호 현황**: 현재 계정·기기·세션, 상태 알림, 별도의 AI 연결, 제공되는 PC 상태 자료를 본다.
- **업무 앱**: 지정한 앱에 대한 접근 판정을 본다. 허용 판정과 실제 접속 성공은 별개다.
- **보안 기록**: 제공된 원천의 접속 기록·XDR 사건 및 근거를 본다. Windows System/Application의 경고·오류 건수는 공격 탐지 수치가 아니다.
- **학생 구현 영역**: 앞선 13~22단계의 학생 작성 화면이다. 공식 0.2.14→0.2.21 업데이트 당시 `student/`를 보존했다. 이후 사용자 지정 대시보드 작업으로 `student/extension.mjs`와 `student/appearance.json`이 별도로 추가·수정됐으며 기존 학생 함수는 유지했다.
- **SDP 미연결**: 로컬 PC 자료가 보여도 SDP 자격·원천 서버가 없으면 업무 원천은 계속 미연결로 표시해야 한다.

값을 표시할 때는 `실측 · YYYY-MM-DD HH:mm:ss · 단위`, `예시 · 실측 아님`, `확인 불가 · 이유`를 구분한다. CPU는 %, 메모리는 GB 또는 %, 디스크 남은 공간은 GB처럼 **항목별 단위**를 함께 본다. 조회 실패 시 마지막 값이나 임의 예시로 성공처럼 채우지 않는다.

## 2. 처음 내려받기 — Git 없는 ZIP 방식 (기본)

1. **Git 설치는 필요 없다.** Windows에 Node.js를 설치한다. 수업 검수 기준은 **24.19.0**, 제공 도구의 지원 범위는 **22~24**다.
2. [GitHub 최신 main ZIP](https://github.com/WILDMONSTR/choi-bujang-secret-vault/archive/refs/heads/main.zip)을 다운로드하고 **기존 작업 폴더와 다른 위치**에 압축을 푼다. 보통 `choi-bujang-secret-vault-main` 폴더가 생긴다. 기존 프로젝트·제출물은 지우거나 옮기지 않는다.
3. 일반 권한 PowerShell에서 압축 해제한 `on-client` 폴더로 이동한다(다른 위치에 풀었다면 경로만 변경).

```powershell
cd "$HOME\Downloads\choi-bujang-secret-vault-main\on-client"
node --version
node -p "require('./package.json').version"
node --check .\student\extension.mjs
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
```

버전 `0.2.21`, 문법 오류 없음, 실행 주소 `http://127.0.0.1:5189/`를 확인한다. Node.js를 찾지 못하면 설치 뒤 새 PowerShell을 연다. 이 문서의 수치를 실측이라고 적지 않는다.

**Git은 선택 사항이다.** Git이 이미 설치된 환경에서만 `git clone https://github.com/WILDMONSTR/choi-bujang-secret-vault.git`으로 받을 수 있다. Git이 없는 ZIP 폴더는 `git rev-parse HEAD`가 불가능하므로 [GitHub 커밋 화면](https://github.com/WILDMONSTR/choi-bujang-secret-vault/commits/main)에서 40자리 SHA와 다운로드 시각을 확인하고, 로컬 Git HEAD 검증을 수행했다고 적지 않는다.


## 3. 공식 0.2.21 업데이트 (별도 ZIP 준비 불필요)

**2026-11-02 기준 GitHub `main`은 이미 0.2.21이다. 새 ZIP을 받거나 Git으로 복제했다면 업데이트를 다시 실행할 필요 없이 4장으로 넘어간다.** 아래 절차는 업데이트 이전(0.2.14 등) 버전의 기존 로컬 폴더에만 필요하다. 먼저 `node -p "require('./package.json').version"`으로 확인한다.

제공된 파일 `update-alekov-0.2.21(2).ps1` 자체가 공식 ZIP의 주소·파일 크기·SHA-256을 고정해 두고, **적용 시 공식 ZIP을 직접 내려받아 검증**한다. 인터넷 연결이 필요하다. 새로 받은 0.2.21 ZIP 폴더에는 다시 적용할 필요가 없다.

먼저 업데이트 파일을 Windows의 다운로드 폴더에 저장했는지 확인한다. 다른 위치에 저장했다면 아래 `$updater` 경로만 실제 위치에 맞춘다. 작업 폴더는 `on-client`다.

```powershell
$updater = Join-Path $HOME 'Downloads\update-alekov-0.2.21(2).ps1'
Test-Path -LiteralPath $updater
powershell -NoProfile -ExecutionPolicy Bypass -File $updater -Project (Get-Location).Path
```

`Test-Path` 결과가 `True`여야 한다. 첫 실행은 **미리보기**이므로 파일을 바꾸지 않는다. 이미 최신이면 `ALREADY_LATEST`를 확인하고 종료한다. 기존 버전이면 `DRY_RUN_READY`와 변경할 제공 파일 목록을 확인하고, **앱 실행 창을 Ctrl+C로 종료한 뒤** 다음을 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $updater -Project (Get-Location).Path -Apply
node -p "require('./package.json').version"
powershell -NoProfile -ExecutionPolicy Bypass -File $updater -Project (Get-Location).Path
```

`[완료]`, 패키지 버전 `0.2.21`, 재실행 미리보기의 `ALREADY_LATEST`를 모두 확인해야 적용 성공으로 적는다. 이 업데이트는 공식 제공 파일만 검사·교체한다. `student/`, 제출 문서, `.git`, 계정 연결 설정에는 손대지 않는 계약이다. 원본 제공 파일이 직접 수정됐거나 일부 누락되면 안전하게 거절한다. 이때 `reset`, `clean`, 삭제, 강제 덮어쓰기를 사용하지 않는다.

`UPDATE_ZIP_DOWNLOAD_FAILED`이면 ZIP을 자동으로 받지 못한 것이다. 앱 업데이트 성공이 아니므로 인터넷·공식 배포 서버 접근 여부를 확인한다. `UPDATE_ZIP_HASH_MISMATCH`이면 받은 ZIP은 신뢰하지 않고 적용을 중단한다. 제공 서버가 제공되지 않는 상황에서는 버전을 임의로 0.2.21로 고쳐 표시하지 않는다.

## 4. 앱 실행 — AI 연결을 원할 때 권장하는 한 가지 방법

`on-client` 폴더에서 **관리자 권한 없이** 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
```

서버 실행 안내가 보이면 브라우저에서 `http://127.0.0.1:5189/`을 연다. 브라우저에서 `보호 현황`, `업무 앱`, `보안 기록` 탭을 확인한다. 종료는 **서버를 실행한 PowerShell 창에서 Ctrl+C**다. 브라우저 탭만 닫아서는 서버가 종료되지 않는다.

**왜 `npm.cmd start`는 AI 연결에 불리한가?** 현재 0.2.21에서 `npm start`는 `node src/server.mjs`를 직접 켜지만, `tools/start-alekov.ps1`는 그 전에 이 프로젝트용 계정 연결 Native Host 설정을 자동으로 준비한다. 따라서 기본 `npm.cmd start`로 화면이 열려도 AI 계정 연결 기능이 준비됐다고 볼 수 없다. 0.2.21에서도 제공 실행 안내와 실제 연결 상태를 확인한다. `-Demo`는 **실제 연결이 아닌 예시**, `-NoNativeHost`는 **계정 연결을 생략한 확인용**이다.

## 5. 처음 보는 사람용 AI 연결 2단계

**1단계 — ALEPH 계정 연결:** `보호 현황`의 `계정 연결 확인`에서 `계정 연결 시작` → `계정 확인 페이지 열기` → **본인 ALEPH 계정**으로 6자리 번호 확인 → 앱에서 `로그인 확인 완료` → `현재 로그인 확인`. 이것은 AI 앱 승인과 **다른** 절차다.

**2단계 — 앱 AI 연결:** 화면의 `AI 연결 시작` → 앱 승인 번호와 만료 시각 확인 → `승인 페이지 열기` → 같은 ALEPH 계정·프로젝트인지 확인하고 승인 → 앱에서 `승인했으며 연결 확인` → `상태 다시 확인` → 연결이 확인됐을 때만 `현재 API 연결 점검`. AI 연결 완료와 AI 모델 목록 점검, AI 사건 설명 성공은 별개다.

확인 번호·API 비밀값·토큰·개인키·인증서·계정 설정 원문은 GitHub, 스크린샷, 채팅에 올리지 않는다. 다른 사람의 설정 파일을 복사하지 않는다. 연결 준비만으로 실제 운영 데이터나 SDP가 연결되지 않는다.

## 6. 가장 많이 막히는 두 가지

| 증상 또는 오류 | 뜻 | 먼저 할 일 |
|---|---|---|
| `npm.cmd start` 이후 AI 연결 불가 | 서버만 켜졌고 Native Host 자동 준비가 빠졌을 수 있음 | 서버를 Ctrl+C로 종료 → 앱 폴더에서 제공 `start-alekov.ps1`로 실행 → 계정 연결부터 확인 |
| `ALEKOV_CONNECT_OUTCOME_UNKNOWN` | 승인 뒤 연결 결과의 검증 실패 또는 최종 상태 불명. **연결 성공이 아님** | 자동 재시도·강제 초기화하지 말고 `상태 다시 확인` 1회 → `연결 도움정보 보기`의 비밀 없는 오류 코드·시각·phase를 확인해 운영자에게 전달 |
| `ON_AI_PROVISIONING_PENDING` | AI 이용 권한 준비 또는 확인 불가 | 계정 연결·앱 승인 확인 → 계속되면 운영자의 앱 권한·게이트 확인 필요 |
| `WB_CLCO_INVALID_RESPONSE` | AI 게이트 응답 형식·모델 목록 계약 불일치 가능 | 모델 권한과 게이트 호환 버전을 운영자에게 확인 |
| `ENGINE_NOT_CONNECTED` | 업무 원천 SDP 연결 없음 | AI 연결 성공 여부와 섞지 않는다. 본인 SDP 설정은 운영자가 별도 안내 |
| `CONTRACT_MISMATCH`, `ENGINE_RESULT_UNVERIFIED` | 원천 데이터 계약이나 확인 범위를 검증하지 못함 | `다시 불러오기` 한 번 → 도움정보 확인 → 담당자에게 전달 |
| 포트 5189 사용 중 | 다른 앱이 같은 포트를 사용 | 기존 프로그램을 강제 종료하지 않고 `-Port 5190`을 붙여 실행하고 브라우저도 `:5190`으로 접속 |
| 권한 없음·값 읽기 실패 | 일반 계정으로 읽을 수 없는 정보 | 관리자 권한 상승 대신 `확인 불가`와 이유 표시. 방화벽 설정 변경 금지 |

이전에도 `ALEKOV_CONNECT_OUTCOME_UNKNOWN`이 발생했다는 사실만으로 업데이트가 해결한다고 단정할 수 없다. 문제의 소재는 **계정 승인 뒤 자격 보관·원천 응답 검증 또는 운영자 서버**에 있을 수 있고, 실제 로그 확인 전까지 한 원인으로 확정하지 않는다.

## 7. 관제형 화면 점검 기준

목표 화면은 **상단 상태 카드 네 개**, 아래에 **추이 비교·기록**이다. 화면의 디자인보다 **실제 측정인지, 조회됐는지, 원천이 무엇인지**가 중요하다. 제공 PC 상태 조회가 있다면 CPU·메모리·디스크 수집기를 또 만들지 않는다.

| 항목 | 통과 기준 |
|---|---|
| CPU·메모리·디스크 | 실제 조회값에 측정 시각과 단위. 실패한 항목은 `확인 불가`·사유 |
| 추이 | 같은 단위·측정 범위의 서로 다른 시각 값만 비교. 예시 값을 측정치에 섞지 않음 |
| 네트워크·방화벽 | 읽기 전용 조회. 조회하지 못하면 실패 이유. 보안 설정 변경 없음 |
| Windows System·Application 기록 | 경고·오류 건수와 기간을 표시하고 **'침해·공격 탐지 결과가 아닙니다'** 명시 |
| SDP·AI | PC 로컬 조회, SDP 원천 연결, AI 앱 승인, AI API 점검을 별도 표시 |
| 사용성 | 직접 누르는 `다시 조회`, 조회 중 표시, 오류·다음 행동 안내, Tab/Enter/Space로 조작 |
| 기능 미제공 | 실제 조회가 없는 항목은 `아직 미구현` 또는 `확인 불가`; 임의 숫자 사용 금지 |

**검증 주의:** 문서만으로 Windows PC의 실제 화면·실측을 증명할 수 없다. 학생 대시보드는 `student/extension.mjs`에서 구현했고, 제공 공통 화면·서버는 수정하지 않았다. 실제 PC 조회 결과는 해당 PC에서 확인해야 한다.

## 8. 다른 사람도 같은 결과를 만드는 확인 순서

1. GitHub에서 ZIP 다운로드(기본) 또는 Git 복제(선택) → `on-client` 진입 → `node --version`, `package.json` 버전 `0.2.21` 확인.
2. 버전이 이미 `0.2.21`이면 업데이트를 생략한다. 구버전 폴더만 첨부 업데이트 스크립트 **미리보기** → `-Apply` → 0.2.21/해시 검증 → 다시 미리보기에서 `ALREADY_LATEST`.
3. `start-alekov.ps1` 실행 → 브라우저 주소 접속 → 세 탭 확인 → 계정 연결과 AI 앱 승인 각각 점검.
4. PC 상태가 실제로 조회된다면 항목별 단위·측정 시각을 기록. 실패·SDP 미연결·AI 연결 불명은 그대로 기록.
5. 앱 종료·재실행 → 오류 발생 시 6장 표와 화면의 도움정보를 비교.
6. **Git 없는 ZIP 이용자**는 GitHub의 `main` 커밋과 ZIP 다운로드 시점을 확인한다. `git status`나 `git rev-parse HEAD` 실행은 요구하지 않는다. **Git 이용자만** 변경 파일과 비밀값 포함 여부를 검토하고 `git status --short` → `git diff --stat` → 변경 파일만 `git add` → `git commit` → `git push`한다. push가 거절되면 **`--force` 없이** 원격 변경과 권한부터 확인한다.
7. Git 사용자는 `git rev-parse HEAD`로 40자리 SHA를 확인한다. Git 미설치 사용자는 GitHub `main` 커밋 화면에서 SHA를 확인하며 로컬 HEAD를 검증했다고 주장하지 않는다.

저장소: https://github.com/WILDMONSTR/choi-bujang-secret-vault

**검증 범위(2026-11-02):** 공식 0.2.21 ZIP(463,517바이트, SHA-256 `289a109cfc38e7963b9f973a381cf81aec552c0f1ffca59c9a354585e7c511da`)을 GitHub Actions 환경에서 검증하고 제공 파일 38개를 반영했다(PR #15). **공식 업데이트 당시** `student/` 변경은 0개였으며 이후 학생 대시보드와 그래프를 별도 커밋(PR #16·#17)으로 구현했다. 사용자가 계정 연결·AI 연결·AI 점검 성공을 보고했지만, 이 문서 작성 과정에서 사용자 Windows PC의 실측값이나 화면을 직접 수집·검증한 것은 아니다.


## 9. 마지막 6단계: 0.2.21 학생 관제 대시보드 (2026-11-02)

**실행 위치:** GitHub ZIP을 압축 해제하거나 Git으로 복제한 저장소의 `on-client` 폴더. GitHub `main`이 0.2.21이라면 추가 업데이트를 실행하지 않습니다. 일반 PowerShell 권한으로 실행합니다. `npm.cmd start`로 직접 서버를 켜면 계정 연결용 개인 Native Host 자동 준비가 빠질 수 있으므로, 계정·AI 연결을 확인할 때는 아래 제공 실행 도구를 권장합니다.

```powershell
# 압축을 푼 on-client 폴더에서 실행 (Git·NPM 필요 없음)
node --version
node -p "require('./package.json').version"
node --check .\student\extension.mjs
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
```

브라우저에서 `http://127.0.0.1:5189/` → **보호 현황** → **학생 상태·알림 표시** 내부의 **겨울철방어 · 개인 관제 대시보드**를 확인합니다. 아래 4개 카드는 설명용 숫자를 넣지 않는 학생 추가 요약입니다. 카드 4개는 화면 너비에 맞춰 **2열×2행**으로 배치되며, 그 아래 **CPU·메모리 추이 그래프 카드 2개와 측정 기록**이 있습니다. 별도의 제공 **내 PC 상태** 카드는 그대로 남아 있습니다.

1. **기능 점검표**: 기존 보안 기록, PC 상태, 위험 알림을 별도 출처로 구분합니다. 표의 안내는 해당 기능의 실제 원천 조회 성공을 대신하지 않습니다.
2. **내 PC 상태**: CPU %, 메모리 GB, 디스크 여유 GB와 항목별 실측 시각·단위를 표시합니다. **정상 수치가 있는 항목에만 시각적 `<progress>` 진행 막대**(CPU 사용률·메모리 사용률·디스크 여유 비율)를 표시합니다. 새 수집기나 Windows 명령을 학생 파일에서 실행하지 않고 기존 읽기 전용 `studentApi.get('/api/pc/status')` 결과만 사용합니다.
3. **연결과 기록**: 네트워크 인터페이스/IPv4 개수, 방화벽 Domain·Private·Public 설정, 최근 24시간 Windows System·Application 경고/오류 건수를 표시합니다. **Windows 경고·오류 건수는 침해 또는 공격 탐지 결과가 아닙니다.** 현재 SDP 연결 여부는 별도입니다. `disconnected`면 **SDP 미연결**, `demo`면 예시로 표시하고, `connected` 모드라도 실제 SDP 성공은 제공 연결 화면을 따로 확인해야 합니다.
4. **내 앱 · 조회**: `다시 조회`를 누를 때만 새 요청을 보내며 조회 중 표시·버튼 잠금·오류 후 다음 행동을 안내합니다. 키보드 **Tab → Enter 또는 Space**로 실행할 수 있습니다.

4개 카드 **아래**에는 **측정 추이**(직전 두 실측의 CPU 변화 단위 %p·메모리 사용량 변화 단위 GB), **CPU 사용률(%) SVG 그래프 카드**, **메모리 사용량(GB) SVG 그래프 카드**, 그리고 **측정 기록**(최대 8회)이 있습니다. 두 번 이상 다른 시각에 직접 조회해야 그래프 점이 2개 이상 나타납니다. 수치가 누락되면 그래프에는 가짜 점을 넣지 않고 해당 구간도 연결하지 않습니다. 새 측정값이 하나도 없거나 해당 항목만 실패하면 '확인 불가' 또는 '비교 부족'으로 표시합니다. 지난 기록은 **이 브라우저 세션의 과거 실측**이며 현재 값을 대신하지 않습니다. 페이지 새로고침·재시작 시 기록은 초기화됩니다. `<progress>`와 SVG는 학생 코드에서 표준 DOM으로 생성하며 제공 CSS·공통 화면·서버 파일은 수정하지 않습니다.

**실패 확인:** 조회를 누르기 전에는 `아직 조회하지 않음`이어야 합니다. 조회 중에는 `조회 중`으로, 실패 후에는 `이번 조회 실패` 및 오류 코드·다시 조회 안내로 바뀝니다. 일반 권한으로 읽지 못한 개별 항목은 `확인 불가`와 권한 사유를 표시합니다. 예시 값·마지막 성공 값을 현재 실측처럼 대체하지 않습니다. 이 문서에 적은 문구는 **예상 화면 확인 기준**이며 사용자 PC에서의 실측값은 기록하지 않았습니다.

### 처음 사용하는 사람의 연결 실패 분기

- **`npm.cmd start`에서 AI가 안 되면:** 실행 중인 서버를 Ctrl+C로 종료 → `start-alekov.ps1`로 재실행 → '계정 연결 확인'에서 로그인 확인 → 별도 'AI 연결'의 앱 승인 → '현재 API 연결 점검'. 앱이 열리는 것과 AI 연결은 별개입니다.
- **`ALEKOV_CONNECT_OUTCOME_UNKNOWN`:** 승인했더라도 최종 연결 결과를 확인할 수 없다는 의미. `상태 다시 확인` 한 번 → `연결 도움정보 보기`로 코드·시각·phase 확인 → 계속되면 담당자에게 전달. 연결됐다고 표시하거나 임의 키를 넣지 않습니다.
- **`SDP 미연결`:** PC 실측은 별개로 볼 수 있습니다. SDP/업무 원천을 사용하려면 운영자가 발급한 별도 설정이 필요합니다. `sudo`·관리자 PowerShell·방화벽 변경을 시도하지 않습니다.

### 제출용 확인

Git 저장소 **최상위**로 돌아온 후 `git status --short`, `git diff --stat`, `git rev-parse HEAD`, `git remote -v`를 확인합니다. 변경된 파일을 읽고 비밀값이 없을 때 필요한 파일만 커밋·push합니다. `git push`가 거절되면 원격 변경이나 권한부터 확인하며 `--force`는 사용하지 않습니다. `npm run package-app`은 실행하지 않고 새 포장 스크립트도 만들지 않습니다.

사용자 PC에서 실제로 측정한 값이나 AI 연결 성공, SDP 연결 성공을 이 문서 작성·커밋만으로 인증하지 않습니다.


### Git·NPM이 없는 Windows PC에서 최신 대시보드로 갱신하기

**Git과 NPM 명령어는 필요 없습니다.** [GitHub main ZIP](https://github.com/WILDMONSTR/choi-bujang-secret-vault/archive/refs/heads/main.zip)을 다운로드합니다. 기존 0.2.21 앱의 AI 계정 연결이 이미 성공했다면 **프로젝트 폴더를 이동하거나 삭제하지 말고** 아래 절차로 파일 3개만 교체합니다.

1. 기존 앱 실행 PowerShell에서 **Ctrl+C**로 서버를 종료합니다. 기존 앱 폴더는 그대로 둡니다.
2. ZIP은 별도 폴더에 풀고 그 안의 `on-client/student/extension.mjs`, `on-client/docs/KESHEV_FIRST_RUN_20261102.md`, `on-client/docs/STUDENT_RUNBOOK.md`를 기존 앱의 동일 상대경로에 덮어씁니다. `student/appearance.json`, 개인 Native Host·SDP 설정, 기타 학생 파일·제출물은 이동·삭제하지 않습니다. 변경 전 파일은 별도로 백업할 수 있습니다.
3. **기존** `on-client` 폴더에서 아래 명령만 실행합니다.

```powershell
node -p "require('./package.json').version"
node --check .\student\extension.mjs
Select-String .\student\extension.mjs -Pattern 'trendChart|progressMetric'
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
```

`0.2.21`과 문법 검사 종료 코드 `0`, 검색 결과에서 `trendChart`·`progressMetric`이 보이는지 확인합니다. 브라우저 `http://127.0.0.1:5189/` → **보호 현황 → 학생 상태·알림 표시 → 겨울철방어 · 개인 관제 대시보드** → **다시 조회** 2회(다른 측정 시각)를 누릅니다. CPU·메모리·디스크 진행 막대, CPU·메모리 그래프 카드, 최대 8회 기록을 확인합니다. 측정에 실패하면 막대·그래프 점을 임의로 채우지 않고 `확인 불가`와 이유를 표시합니다. Windows 경고/오류 건수는 **공격 탐지 결과가 아닙니다**. AI 연결 성공과 PC 조회 결과도 별도로 봅니다.

**검증 경계:** 그래프의 실제 숫자는 해당 PC에서 조회한 뒤에만 확인할 수 있습니다. GitHub에서 확인한 40자리 커밋은 저장소 커밋이며, Git 없는 ZIP 폴더에서는 `git rev-parse HEAD`를 실행할 수 없습니다. 포장 명령이나 관리자 권한은 필요하지 않습니다.
