# XDR 보너스 경보

이 폴더는 보너스 여섯 개의 연습 경보입니다. 경보는 수업용으로 만든 Wazuh 모양이며, 실제 로그가 아닙니다. 정답은 이 저장소에 없습니다.

## 경보 묶음

`xdr/fixtures/<moduleKey>.json` 을 읽습니다. `moduleKey` 는 아래 여섯 개입니다.

| moduleKey | 보는 것 |
|---|---|
| `brute-force` | 짧은 시간에 몰린 로그인 실패 |
| `web-injection` | 웹 요청에 섞인 주입 형태 |
| `known-cve` | 이미 공개된 취약점을 노린 요청 형태 |
| `persistence` | 다시 켜도 남도록 심긴 서비스·예약 작업 |
| `privilege` | 평범한 계정의 갑작스러운 권한 상승 |
| `exfiltration` | 처음 보는 곳으로 빠지는 큰 전송 |

한 파일에는 명확한 공격, 애매한 시도, 정상 이벤트가 함께 들어 있습니다. 주소는 문서용 대역만 쓰고, 계정은 `user01` 같은 가상 이름입니다. `known-cve` 의 원격 조회 구문은 문서용 표기입니다. 그 문자열을 다른 시스템에 넣거나 변형하지 않습니다.

## 학생이 만드는 파일

항목마다 `xdr/<moduleKey>/decide.mjs` 를 만듭니다. `decide(alert)` 를 내보냅니다. 비동기 함수여도 됩니다. 반환은 아래 세 값입니다.

- `action`: `block`, `alert`, `record` 중 하나
- `confidence`: 0 이상 1 이하 숫자
- `reason`: 짧은 이유

명확한 공격은 `block`, 애매한 시도는 `alert`, 정상 이벤트는 `record` 입니다. 경보 원본은 고치지 않습니다.

## 실행

저장소 루트에서 항목 키 하나를 넣습니다.

```
node scripts/xdr-run.mjs brute-force
```

`npm run xdr:run -- brute-force` 도 같은 명령입니다. 실행기는 해당 경보마다 `decide` 를 부르고, 결과를 `xdr/<moduleKey>/result.json` 에 씁니다. 형식은 `aleph.xdr.result.v1` 이고, `decisions` 에는 경보 id·행동·확신도·이유가, `counts` 에는 `block`·`alert`·`record` 건수가 있습니다.

반환 형식이 틀린 경보는 `record` 로 남고, 오류 한 줄이 출력됩니다. 실행기 자체는 네트워크를 쓰지 않습니다. 판정자는 격리된 환경에서 같은 명령을 다시 실행해 결과를 봅니다. 이미 커밋된 `result.json` 만으로 판정이 끝나지 않습니다.

## 심판 격리 환경에서 지킬 것

심판은 인터넷 없이 `decide.mjs` 한 파일을 불러와 경보마다 바로 답을 받습니다. 이 파일이 돌지 못하면 건수를 셀 수 없어 `XDR_DECIDE_NOT_RUNNING` 으로 끝납니다.

- `decide.mjs` 에는 `import` 문을 두지 않습니다. 필요한 패턴은 `patterns.json` 에서 파일 맨 위 상수로 옮겨 적습니다.
- 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고, 그 파일 안에서 혼자 계산해 답합니다. 경보 하나에 2초 안에 답합니다.
- `confidence`(확신도)는 경보가 패턴과 얼마나 뚜렷하게 맞는지를 `decide` 가 스스로 0~1 로 매긴 값입니다.
- `xdr/alerts.log` 기록과 판정기 연결은 `respond.mjs` 같은 다른 파일에서 합니다. `decide.mjs` 는 판단 결과만 돌려줍니다.

인터넷을 끈 상태에서 `npm run xdr:run -- <moduleKey>` 를 돌려도 같은 결과가 나오면 심판에서도 같은 결과가 나옵니다.

## known-cve: Log4Shell 보너스 방어

- xdr/fixtures/known-cve.json은 CVE-2021-44228(Log4Shell) 관련 명확한 표식, 약한 정황, 정상 이벤트를 섞은 가상 fixture입니다. 실제 PC의 로그나 실제 공격 기록이 아닙니다.
- xdr/known-cve/decide.mjs는 완전한 원격 JNDI 조회 표식, 경보 수준(10 이상), 출발지, CVE 또는 MITRE ATT&CK T1190 근거가 모두 있을 때만 block을 반환합니다. 부분 표식은 alert, 무관한 일반 이벤트는 record입니다. 원문 요청·헤더를 판정 이유에 넣지 않습니다.
- 패턴 참고 자료는 xdr/known-cve/patterns.json에 있습니다: https://nvd.nist.gov/vuln/detail/CVE-2021-44228, https://www.cisa.gov/news-events/alerts/2021/12/22/mitigating-log4shell-and-other-log4j-related-vulnerabilities, https://attack.mitre.org/techniques/T1190/.
- 분류 결과를 xdr/known-cve/result.json에 만들려면 저장소 루트에서 npm run xdr:run -- known-cve를 실행합니다.
- 실제 대응 모듈의 fixture 시뮬레이션과 짧은 기간 차단 규칙 생성을 확인하려면 node xdr/known-cve/respond.mjs를 실행합니다. 이 명령은 공유 xdr/brute-force/deny-rules.json에 xdr-known-cve- 접두사의 15분 제한 규칙을 추가하고, URL·헤더·payload 원문 없이 xdr/alerts.log에 알림/차단 메타데이터를 남깁니다.
- src/xdr-ztna-gate.mjs는 기존 brute-force와 web-injection 검사를 유지하고 known-cve 검사를 추가합니다. 매칭되는 활성 XDR 차단 규칙이 없으면 원래 src/decider.mjs가 계속 최종 ZTNA 정책 결정을 내립니다. src/decider.mjs의 규칙과 응답 계약은 바꾸지 않습니다.

## persistence: 파일 무결성·서비스·예약 작업 지속성 방어

- `xdr/fixtures/persistence.json`은 24건의 가상 경보이며 실제 PC 이벤트가 아닙니다. `xdr/persistence/decide.mjs`는 심판이 단독으로 불러도 실행되도록 import나 파일 입출력 없이 동작합니다.
- 기준 목록에 없는 시작 항목, 임시 경로와 연결된 서명 없는 서비스, 반복된 원격 서비스 등록, 무결성이 바뀐 서명 없는 실행 파일, 임의 이름 예약 작업 등 명확한 복합 증거에만 `block`을 반환합니다. 단발성 변경이나 서명 상태 미확인은 `alert`, 명시된 정상 업데이트·서명된 기존 서비스·읽기 전용 열거는 `record`입니다.
- 패턴 기준: MITRE ATT&CK T1543 https://attack.mitre.org/techniques/T1543/ 및 T1053 https://attack.mitre.org/techniques/T1053/.
- 분류 결과 생성: `npm run xdr:run -- persistence`. 대응 시뮬레이션과 15분 제한 격리 규칙/안전한 로그 작성: `node xdr/persistence/respond.mjs`.
- 대응기는 공유 `xdr/brute-force/deny-rules.json`에 `xdr-persistence-` 접두사의 만료 규칙을 추가합니다. `src/xdr-ztna-gate.mjs`가 신뢰된 엔진이 제공한 출발지 주소의 활성 규칙을 확인한 뒤, 일치 규칙이 없으면 원래 `src/decider.mjs`를 그대로 호출합니다. 경로·사용자명·해시·명령행 원문은 로그에 쓰지 않습니다.


## privilege: 갑작스러운 관리자 권한 상승·세션 거부

- `xdr/fixtures/privilege.json`의 26건은 가상 경보입니다. 테스트용 `identity.subjectId`는 신뢰된 디렉터리에서 정규화해 들어온다는 전제의 가상 계정 ID이며, 실제 사용자 디렉터리나 운영 로그가 아닙니다.
- `xdr/privilege/decide.mjs`는 단일 경보를 판정합니다. 관리자 그룹 변화와 관리자 명령의 직접 결합, 높은 위험도, 출발지, MITRE 기법, 신뢰된 계정 ID가 함께 있어야 `block` 후보로 분류합니다. 단독 변경·낯선 출발지 명령·취소/실패는 `alert`, 평범한 로그인·읽기 조회·비관리자 그룹 변경은 `record`입니다.
- `node xdr/privilege/respond.mjs`는 같은 정규 계정 ID·출발지·계정명인 사건에서 5분 안의 관리자 그룹 추가와 관리자 명령을 함께 확인합니다. 명확한 사건은 `xdr/privilege/session-rules.json`에 계정 ID 기준 15분 거부 규칙으로 기록하고, 알림 로그에는 사용자명 등 원문을 남기지 않습니다.
- `src/xdr-ztna-gate.mjs`는 인증된 `request.subjectId`에 해당하는 활성 privilege 규칙을 먼저 확인합니다. 일치하면 해당 계정의 이후 ZTNA 요청을 거부하고, 일치하지 않으면 기존 XDR 확인과 원래 `src/decider.mjs` 정책 판정을 계속합니다. 원래 판정기 규칙은 바꾸지 않습니다.
- 로컬 검사: `npm run xdr:run -- privilege`, `npm run privilege:test`. 세션 규칙은 fixture 기반 시뮬레이션이며, 실제 IdP 토큰 폐기 API를 직접 호출하지 않습니다. 실제 서비스에 연결하려면 신뢰된 ID 매핑과 세션 폐기 어댑터가 별도로 필요합니다.
