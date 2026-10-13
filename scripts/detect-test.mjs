import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const deviceA = 'aaaaaaaaaaaaaaaa';
const deviceB = 'bbbbbbbbbbbbbbbb';

function reads(count, { intervalSeconds = 2, owner = subject, deviceId = deviceA, start = START } = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalSeconds * 1000).toISOString(),
    method: 'GET', deviceId, identity: { sub: owner },
  }));
}

const proposal = (deviceId) => ({
  action: 'propose_revocation',
  reasonCode: 'burst_read',
  target: { kind: 'virtual_device', deviceId },
});

const cases = [
  { name: '정상 조회 30건', events: reads(30), expected: { action: 'observe' } },
  { name: '10분 안에 120건', events: reads(120), expected: { action: 'observe' } },
  { name: '10분 안에 121건', events: reads(121), expected: proposal(deviceA) },
  { name: '폭주 조회 200건', events: reads(200), expected: proposal(deviceA) },
  { name: '서로 다른 사용자 각 100건', events: [...reads(100),
    ...reads(100, { owner: 'other_fixture' })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: { action: 'observe' } },
  { name: '10분 밖으로 흩어진 조회 200건', events: reads(200,
    { intervalSeconds: 7 }), expected: { action: 'observe' } },
  { name: '같은 주체의 두 기기 각각 100건', events: [...reads(100, { deviceId: deviceA }),
    ...reads(100, { deviceId: deviceB })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: { action: 'observe' } },
  { name: '정상 기기 유지·의심 기기 한 대만 제안', events: [...reads(30, { deviceId: deviceB }),
    ...reads(121, { deviceId: deviceA })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: proposal(deviceA) },
  { name: '여러 기기가 의심되어도 첫 한 대만 제안', events: [...reads(121, { deviceId: deviceA }),
    ...reads(121, { deviceId: deviceB, start: START + 60_000 })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: proposal(deviceA) },
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
    process.stdout.write('가상 사건 연습이며 실제 접속 회수나 심판 통과 증거가 아닙니다.\n');
    if (results.some((item) => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write('탐지 연습 첫 오류: ' + error.message + '\n');
    process.exitCode = 1;
  }
}
