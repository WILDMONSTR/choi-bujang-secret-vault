# 9단계 탐지 연습 사건 계약

\`npm run detect:test\`는 \`src/detect.mjs\`의 \`detect(events)\`에 가상 사건을 전달합니다. 간단한 탐지 레코드와 기존 \`aleph.decision.v1\` 판정 요청 형식을 지원합니다. 판정에는 가명 주체, 확인된 가상 기기, 요청 종류, 판정, 네트워크 및 다량 조회 신호만 사용합니다. 메모 본문·토큰·실명은 저장하거나 출력하지 않습니다.

간단한 탐지 레코드 예시:

\`\`\`js
{
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  deviceId: 'aaaaaaaaaaaaaaaa',
  network: 'first_seen',
  identity: { sub: 'learner_fixture' },
  decision: 'allow'
}
\`\`\`

판정 요청 형식에서 주체는 \`subjectId\`, 기기는 \`deviceId\`, 네트워크는 \`signals.network\`, 다량 조회 요약은 \`recentEvents\`에 있습니다. 요청 종류는 \`method\` 또는 \`requestKind\`로 전달될 수 있습니다. \`decision\`이 있으면 \`allow\`, \`deny\`, \`step_up\` 형식인지 검사하지만 탐지기가 기존 판정을 변경하지 않습니다. 지역은 탐지 조건이 아닙니다.

## 복합 의심 조건

같은 가명 주체와 같은 확인 가상 기기에서 평소와 다른 네트워크(\`first_seen\`)와 다량 조회가 함께 있을 때만 회수 제안을 반환합니다. 다량 조회는 다음 중 하나로 확인합니다.

- 새 네트워크에서 10분 안에 GET 조회가 120건 초과
- \`recentEvents\`에 최근 300초 이내 \`bulk_read\`가 있고 \`count >= 10\`
- \`requestKind: 'bulk_read'\` 요청이 같은 기기에서 300초 안에 10회 이상 반복

별도 결과 예시:

\`\`\`js
{
  action: 'propose_revocation',
  reasonCode: 'burst_read',
  target: { kind: 'virtual_device', deviceId: 'aaaaaaaaaaaaaaaa' }
}
\`\`\`

평소 네트워크의 다량 조회, 새 네트워크 단독, 지역 차이만 있는 사건은 \`{ action: 'observe' }\`입니다. 서로 다른 사용자나 기기의 사건을 합산하지 않습니다. 후보가 여러 개여도 가장 먼저 조건을 만족한 가상 기기 한 대만 제안합니다.

기존 접속 허용·거부 응답은 바꾸지 않습니다. 실제 회수 API나 기기 권한 변경은 구현하지 않습니다. 실제 회수와 첫 의심 사건부터 회수까지의 경과 시간은 심판의 가상 사건 검증 대상이며, 로컬 테스트 통과는 심판 합격 증거가 아닙니다.
