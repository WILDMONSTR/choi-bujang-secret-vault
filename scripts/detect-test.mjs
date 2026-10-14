import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const SUBJECT_A = 'learner_fixture_a';
const SUBJECT_B = 'learner_fixture_b';

function reads(count, {
  owner = SUBJECT_A,
  method = 'GET',
  intervalMs = 1000,
  start = START,
  extra = {},
} = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalMs).toISOString(),
    method,
    identity: { sub: owner },
    ...extra,
  }));
}

const observe = { action: 'observe' };
const proposal = (subject) => ({
  action: 'propose_revocation',
  reasonCode: 'burst_read',
  subject,
});

const cases = [
  {
    name: 'GET 30건은 observe',
    events: reads(30),
    expected: observe,
  },
  {
    name: 'GET 정확히 120건은 observe',
    events: reads(120, { intervalMs: 5000 }),
    expected: observe,
  },
  {
    name: '10분 경계 포함 121건이면 제안',
    events: reads(121, { intervalMs: 5000 }),
    expected: proposal(SUBJECT_A),
  },
  {
    name: '10분 안의 GET 121건이면 제안',
    events: reads(121, { intervalMs: 1000 }),
    expected: proposal(SUBJECT_A),
  },
  {
    name: '모든 10분 구간에 120건 이하이면 observe',
    events: reads(121, { intervalMs: 6001 }),
    expected: observe,
  },
  {
    name: '다른 사용자 두 명의 GET 100건씩은 합산하지 않음',
    events: [
      ...reads(100, { owner: SUBJECT_A }),
      ...reads(100, { owner: SUBJECT_B }),
    ],
    expected: observe,
  },
  {
    name: 'A의 GET 121건과 B의 GET 100건은 A만 제안',
    events: [
      ...reads(100, { owner: SUBJECT_B }),
      ...reads(121, { owner: SUBJECT_A }),
    ],
    expected: proposal(SUBJECT_A),
  },
  {
    name: '동일 사용자의 GET 121건을 순서가 섞여도 집계',
    events: [
      ...reads(61, { start: START }),
      ...reads(60, { start: START + 500 }),
    ].sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0)),
    expected: proposal(SUBJECT_A),
  },
  {
    name: 'GET이 아닌 POST 200건은 observe',
    events: reads(200, { method: 'POST' }),
    expected: observe,
  },
  {
    name: '기기와 네트워크 값 없이도 세 필드 계약으로 제안',
    events: reads(121),
    expected: proposal(SUBJECT_A),
  },
  {
    name: '추가 메타데이터는 사용하지 않고 정확한 응답만 반환',
    events: reads(121, {
      extra: {
        deviceId: null,
        network: null,
        memoBody: 'PRIVATE BODY',
        token: 'PRIVATE TOKEN',
      },
    }),
    expected: proposal(SUBJECT_A),
  },
  {
    name: '단일 사건 객체도 받아 정상 관찰',
    events: {
      at: new Date(START).toISOString(),
      method: 'GET',
      identity: { sub: SUBJECT_A },
    },
    expected: observe,
  },
  {
    name: 'GET이 아닌 사건은 GET 건수에 포함하지 않음',
    events: [
      ...reads(120),
      ...reads(20, { method: 'POST', start: START + 100 }),
    ],
    expected: observe,
  },
  {
    name: '다른 사용자의 다량 사건이 있어도 대상 사용자는 별도 계산',
    events: [
      ...reads(121, { owner: SUBJECT_A }),
      ...reads(121, { owner: SUBJECT_B, start: START + 20_000 }),
    ],
    expected: proposal(SUBJECT_A),
  },
  {
    name: '정확한 10분 구간 밖으로 분산된 121건은 observe',
    events: reads(121, { intervalMs: 6001 }),
    expected: observe,
  },
];

export async function checkDetection(detect) {
  if (typeof detect !== 'function') {
    throw new TypeError('src/detect.mjs에서 detect 함수를 내보내야 합니다.');
  }

  const results = [];
  for (const item of cases) {
    let passed = false;
    try {
      const actual = await detect(item.events);
      passed = isDeepStrictEqual(actual, item.expected);
    } catch {
      passed = false;
    }
    results.push({ name: item.name, passed });
  }

  const invalidCases = [
    {
      name: '시각 누락 사건은 거부',
      event: { method: 'GET', identity: { sub: SUBJECT_A } },
    },
    {
      name: '주체 누락 사건은 거부',
      event: { at: new Date(START).toISOString(), method: 'GET', identity: {} },
    },
    {
      name: '잘못된 시각 사건은 거부',
      event: { at: 'not-a-time', method: 'GET', identity: { sub: SUBJECT_A } },
    },
  ];
  for (const item of invalidCases) {
    let rejected = false;
    try {
      await detect([item.event]);
    } catch {
      rejected = true;
    }
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
