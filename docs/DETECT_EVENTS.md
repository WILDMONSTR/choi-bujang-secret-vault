# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 학생이 작성한 `src/detect.mjs`의 `detect(events)`에 가상 조회 사건을 전달합니다. 각 사건은 다음 네 필드만 가집니다.

```js
{
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  deviceId: 'aaaaaaaaaaaaaaaa',
  identity: { sub: 'learner_fixture' }
}
```

- `at`는 UTC ISO 밀리초 시각이고, `method`는 대문자 HTTP 동작입니다.
- `identity.sub`는 운영 반 엔진이 확인한 가명 주체 ID입니다.
- `deviceId`는 운영 반 엔진이 확인한 가상 기기의 16자리 소문자 16진수 ID입니다. 브라우저가 보낸 ID를 확인된 기기라고 간주하지 않습니다.
- 알 수 없는 필드, 기기 ID 누락·형식 오류, 잘못된 시각 및 잘못된 신원은 `invalid_detection_event`로 거부합니다.

같은 `identity.sub`와 같은 확인된 `deviceId`의 `GET` 사건이 어느 10분 구간에서든 **120건을 넘을 때만** 별도 탐지 결과로 아래 제안을 반환합니다.

```js
{
  action: 'propose_revocation',
  reasonCode: 'burst_read',
  target: {
    kind: 'virtual_device',
    deviceId: 'aaaaaaaaaaaaaaaa'
  }
}
```

정확히 120건은 제안 대상이 아닙니다. 사용자나 기기 사이의 조회를 합산하지 않습니다. 같은 주체의 기기 두 대가 각각 100건만 조회하면 `{ action: 'observe' }`입니다. 여러 기기가 기준을 넘으면 기준 초과 시각이 가장 이른 가상 기기 한 대만 대상으로 선택합니다. 초과 시각이 같으면 `deviceId`가 사전순으로 앞선 한 대를 선택합니다. `POST`, `PUT`, `PATCH`, `DELETE`는 조회 폭주 수에 포함하지 않습니다.

이 계약의 사건은 **로컬 연습용**입니다. 운영 반 엔진이 검증한 사건 전달 경로가 별도로 있어야 하며, 이 탐지기는 제안만 반환합니다. 실제 회수 API를 호출하거나 기기 권한을 바꾸지 않습니다. 실제 회수와 첫 의심 사건부터의 경과 시간은 운영 심판이 가상 사건으로 확인해야 하며, 로컬 시험 결과는 심판 판정이 아닙니다.
