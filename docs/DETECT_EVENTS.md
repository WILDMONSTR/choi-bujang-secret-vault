# 9단계 탐지 연습 사건 계약

\`npm run detect:test\`는 학생이 작성한 \`src/detect.mjs\`의 \`detect(events)\`에 가상 조회 사건을 전달합니다. 사건에는 다음 다섯 필드가 반드시 있어야 하며, \`region\`은 선택적 문맥 정보입니다.

\`\`\`js
{
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  deviceId: 'aaaaaaaaaaaaaaaa',
  network: 'first_seen', // 'usual' | 'first_seen' | 'unknown'
  region: 'foreign',     // 선택 사항. 탐지 조건으로 사용하지 않음
  identity: { sub: 'learner_fixture' }
}
\`\`\`

- \`at\`는 UTC ISO 밀리초 시각이고, \`method\`는 대문자 HTTP 동작입니다.
- \`identity.sub\`는 운영 반 엔진이 확인한 가명 주체 ID입니다.
- \`deviceId\`는 운영 반 엔진이 확인한 가상 기기의 16자리 소문자 16진수 ID입니다. 브라우저가 보낸 ID를 확인된 기기로 간주하지 않습니다.
- \`network\`는 운영 반 엔진이 확인한 네트워크 상태입니다. \`usual\`은 평소 네트워크, \`first_seen\`은 이전에 관측되지 않은 네트워크, \`unknown\`은 확인할 수 없는 상태입니다. 이 값은 브라우저가 임의로 지정하면 안 됩니다.
- \`region\`은 기록에 포함될 수 있지만, 지역 차이만으로 탐지하지 않습니다. 알 수 없는 추가 필드, 네트워크 상태 누락·오류, 기기 ID 누락·형식 오류, 잘못된 시각 및 신원은 \`invalid_detection_event\`로 거부합니다.

## 복합 의심 조건

동일한 \`identity.sub\`와 \`deviceId\`에서 \`network: 'first_seen'\`으로 검증된 \`GET\` 사건이 어느 10분 구간에서든 **120건을 넘을 때만** 별도 탐지 결과로 아래 회수 제안을 반환합니다.

\`\`\`js
{
  action: 'propose_revocation',
  reasonCode: 'unusual_network_burst_read',
  target: {
    kind: 'virtual_device',
    deviceId: 'aaaaaaaaaaaaaaaa'
  }
}
\`\`\`

평소 네트워크에서만 조회가 많거나 새 네트워크에서 조회가 120건 이하라면 \`{ action: 'observe' }\`입니다. 지역이 달라 보이는 것만으로는 제안하지 않습니다. 서로 다른 사용자·기기·네트워크 상태의 요청을 합산하지 않습니다. 여러 기기가 기준을 넘으면 기준 초과 시각이 가장 이른 확인된 가상 기기 한 대만 대상으로 선택합니다. \`POST\`, \`PUT\`, \`PATCH\`, \`DELETE\`는 조회 폭주 수에 포함하지 않습니다.

이 계약의 사건은 **로컬 연습용**입니다. 운영 반 엔진이 검증한 사건 전달 경로가 별도로 있어야 하며, 이 탐지기는 제안만 반환합니다. 실제 회수 API를 호출하거나 기기 권한을 바꾸지 않습니다. 실제 회수와 첫 의심 사건부터의 경과 시간은 운영 심판이 가상 사건으로 확인해야 하며, 로컬 시험 결과는 심판 판정이 아닙니다.
