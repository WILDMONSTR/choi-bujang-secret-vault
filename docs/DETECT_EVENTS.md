# 9단계 탐지 연습 사건 계약

\`npm run detect:test\`는 \`src/detect.mjs\`의 \`detect(events)\`에 가상 사건 목록을 전달합니다. 사건은 간단한 탐지 레코드 또는 기존 \`aleph.decision.v1\` 요청 레코드 형태를 사용할 수 있습니다.

간단한 탐지 레코드 예시:

\`\`\`js
{
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  deviceId: 'aaaaaaaaaaaaaaaa',
  network: 'first_seen', // 'usual' | 'first_seen' | 'unknown'
  identity: { sub: 'learner_fixture' },
  recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }]
}
\`\`\`

기존 판정 요청 레코드에서는 신원은 \`subjectId\`, 네트워크는 \`signals.network\`에 있습니다. 두 형식 모두 \`deviceId\`는 확인된 가상 기기의 16자리 소문자 16진수 ID여야 합니다. 이 값은 브라우저가 보낸 미검증 기기 식별자가 아니라 운영 반 엔진이 확인한 값이어야 합니다.

## 복합 의심 조건

탐지기는 동일한 주체와 동일한 가상 기기에서 **평소와 다른 네트워크(\`first_seen\`) + 갑작스러운 다량 조회**가 함께 나타날 때만 회수 제안을 반환합니다. 다량 조회는 다음 중 하나로 확인합니다.

- 동일 주체·기기의 새 네트워크 GET 요청이 어느 10분 구간에서든 120건 초과
- 현재 GET 요청의 \`recentEvents\`에 300초 이내의 \`bulk_read\`가 있고 \`count >= 10\`

제안 결과:

\`\`\`js
{
  action: 'propose_revocation',
  reasonCode: 'burst_read',
  target: {
    kind: 'virtual_device',
    deviceId: 'aaaaaaaaaaaaaaaa'
  }
}
\`\`\`

정상 네트워크의 다량 조회, 새 네트워크에서 다량 조회 신호가 없는 사건, 지역 정보만 다른 사건은 \`{ action: 'observe' }\`입니다. 서로 다른 사용자나 기기의 신호를 합산하지 않습니다. 여러 후보가 있으면 가장 먼저 조건을 만족한 가상 기기 한 대만 고릅니다.

이 모듈은 기존 접속 허용·거부 응답을 바꾸지 않으며, 제안만 반환합니다. 실제 회수 API를 만들거나 기기 권한을 변경하지 않습니다. 운영 반 엔진의 사건 전달, 실제 회수 및 첫 의심 사건부터의 경과 시간은 심판이 가상 사건으로 확인해야 합니다. 로컬 테스트는 심판 합격 증거가 아닙니다.
