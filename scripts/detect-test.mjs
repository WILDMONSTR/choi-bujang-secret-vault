import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const deviceA = 'aaaaaaaaaaaaaaaa';
const deviceB = 'bbbbbbbbbbbbbbbb';

function reads(count, {
  intervalSeconds = 2, owner = subject, deviceId = deviceA,
  network = 'usual', region = 'local', start = START, recentEvents,
} = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalSeconds * 1000).toISOString(),
    method: 'GET', deviceId, network, region, identity: { sub: owner },
    ...(recentEvents ? { recentEvents } : {}),
  }));
}

function decisionRequest({
  owner = subject, deviceId = deviceA, network = 'first_seen',
  region = 'foreign', recentEvents = [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }],
  method = 'GET', at = new Date(START).toISOString(),
} = {}) {
  return {
    schema: 'aleph.decision.v1',
    requestId: 'fixture-request',
    classId: 'class_fixture',
    projectId: 'project_fixture',
    subjectId: owner,
    deviceId,
    service: 'notes',
    method,
    path: '/notes/demo',
    route: 'GET /notes/:id',
    queryLength: 0,
    querySha256: '0'.repeat(64),
    at,
    policyRevision: 1,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents,
    signals: { source: 'judge_fixture', region, network, hour: 3 },
  };
}

const proposal = (deviceId) => ({
  action: 'propose_revocation',
  reasonCode: 'burst_read',
  target: { kind: 'virtual_device', deviceId },
});

const cases = [
  { name: '정상 조회 30건', events: reads(30), expected: { action: 'observe' } },
  { name: '평소 네트워크의 121건은 단독으로 제안하지 않음',
    events: reads(121), expected: { action: 'observe' } },
  { name: '새 네트워크에서 정확히 120건은 observe',
    events: reads(120, { network: 'first_seen' }), expected: { action: 'observe' } },
  { name: '새 네트워크에서 121건이면 가상 기기 한 대 제안',
    events: reads(121, { network: 'first_seen' }), expected: proposal(deviceA) },
  { name: '정상·의심 기기가 섞여도 의심 기기만 제안', events: [
    ...reads(30, { deviceId: deviceB, network: 'usual' }),
    ...reads(121, { deviceId: deviceA, network: 'first_seen' }),
  ].sort((a, b) => a.at.localeCompare(b.at)), expected: proposal(deviceA) },
  { name: '같은 주체의 두 기기 각각 100건은 observe', events: [
    ...reads(100, { deviceId: deviceA, network: 'first_seen' }),
    ...reads(100, { deviceId: deviceB, network: 'first_seen' }),
  ].sort((a, b) => a.at.localeCompare(b.at)), expected: { action: 'observe' } },
  { name: '다른 사용자 각 100건은 합산하지 않음', events: [
    ...reads(100, { owner: subject, network: 'first_seen' }),
    ...reads(100, { owner: 'other_fixture', network: 'first_seen' }),
  ].sort((a, b) => a.at.localeCompare(b.at)), expected: { action: 'observe' } },
  { name: '새 네트워크와 bulk_read 신호가 있는 공식 요청 형식은 제안',
    events: [decisionRequest()], expected: proposal(deviceA) },
  { name: '새 네트워크만 있고 bulk_read 신호가 없으면 observe',
    events: [decisionRequest({ recentEvents: [] })], expected: { action: 'observe' } },
  { name: '지역만 다르고 네트워크는 평소이면 observe',
    events: [decisionRequest({ network: 'usual', recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }] })],
    expected: { action: 'observe' } },
  { name: 'bulk_read가 5분보다 오래됐으면 observe',
    events: [decisionRequest({ recentEvents: [{ kind: 'bulk_read', ageSeconds: 301, count: 20 }] })],
    expected: { action: 'observe' } },
  { name: 'bulk_read 건수가 기준 미만이면 observe',
    events: [decisionRequest({ recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 9 }] })],
    expected: { action: 'observe' } },
  { name: 'POST 다량 요청은 회수 제안을 내지 않음',
    events: [decisionRequest({ method: 'POST' })], expected: { action: 'observe' } },
  { name: '지역 값만 다르고 신규 네트워크가 아니면 제안하지 않음',
    events: reads(121, { network: 'usual', region: 'foreign' }), expected: { action: 'observe' } },
  { name: '10분 밖으로 흩어진 새 네트워크 조회 200건은 observe',
    events: reads(200, { intervalSeconds: 7, network: 'first_seen' }),
    expected: { action: 'observe' } },
  { name: '두 후보 중 최초 제안 한 대만 선택', events: [
    ...reads(121, { deviceId: deviceA, network: 'first_seen' }),
    ...reads(121, { deviceId: deviceB, network: 'first_seen', start: START + 60_000 }),
  ].sort((a, b) => a.at.localeCompare(b.at)), expected: proposal(deviceA) },
];

export async function checkDetection(detect) {
  if (typeof detect !== 'function') throw new TypeError('src/detect.mjs에서 detect 함수를 내보내야 합니다.');
  const results = [];
  for (const item of cases) {
    const actual = await detect(item.events);
    results.push({ name: item.name, passed: isDeepStrictEqual(actual, item.expected) });
  }

  const invalidCases = [
    { name: '기기 ID 누락 거부', event: (() => { const { deviceId, ...event } = reads(1)[0]; return event; })() },
    { name: '기기 ID 형식 오류 거부', event: reads(1, { deviceId: 'not-a-device' })[0] },
    { name: '알 수 없는 필드 거부', event: { ...reads(1)[0], geo: 'foreign' } },
  ];
  for (const item of invalidCases) {
    let rejected = false;
    try { await detect([item.event]); } catch { rejected = true; }
    results.push({ name: item.name, passed: rejected });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { detect } = await import('../src/detect.mjs');
    const results = await checkDetection(detect);
    for (const item of results) {
      process.stdout.write((item.passed ? '통과' : '확인 필요') + ' · ' + item.name + '\n');
    }
    process.stdout.write('가상 사건 연습이며 실제 회수나 심판 통과 증거가 아닙니다.\n');
    if (results.some((item) => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write('탐지 연습 첫 오류: ' + error.message + '\n');
    process.exitCode = 1;
  }
}
