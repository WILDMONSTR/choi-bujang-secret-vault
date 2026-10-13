import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(input, output, ruleIds) {
  return output && typeof output === 'object' && !Array.isArray(output)
    && Object.keys(output).sort().join(',') === RESPONSE_KEYS
    && output.schema === 'aleph.decision.v1'
    && output.requestId === input.requestId
    && ['allow', 'deny', 'step_up'].includes(output.decision)
    && typeof output.reasonCode === 'string'
    && Array.isArray(output.ruleIds) && output.ruleIds.length > 0
    && output.ruleIds.every((id) => ruleIds.includes(id));
}

export async function checkDecider({ decide, ruleIds }) {
  for (const id of [
    'device_registered', 'signal_provenance', 'resource_scope',
    'instructor_role_required', 'unusual_access_context', 'step_up_required'
  ]) {
    if (typeof decide !== 'function' || !Array.isArray(ruleIds) || !ruleIds.includes(id)) {
      throw new Error(`필수 판정 규칙이 없습니다: ${id}`);
    }
  }

  const { normal, suspicious } = fixtureRequests();
  const announcementId = randomUUID();
  const unavailableSignals = {
    ...normal,
    requestId: randomUUID(),
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null }
  };
  const missingRegion = {
    ...normal, requestId: randomUUID(),
    signals: { source: 'judge_fixture', network: 'usual', hour: 14 }
  };
  const missingHour = {
    ...normal, requestId: randomUUID(),
    signals: { ...normal.signals, hour: null }
  };
  const missingBehavior = { ...normal, requestId: randomUUID() };
  delete missingBehavior.recentEvents;

  const checks = [
    { name: '정상 자기 메모 단건 읽기', request: normal, decision: 'allow', reasonCode: 'approved' },
    { name: '엔진이 신호 미제공을 명시한 정상 단건 읽기', request: unavailableSignals, decision: 'allow', reasonCode: 'approved' },
    { name: '메모 전체 목록 GET /notes 거부', request: { ...normal, requestId: randomUUID(),
      path: '/notes', route: 'GET /notes' }, decision: 'deny', ruleId: 'resource_scope' },
    { name: '메모 전체 목록 API 별칭 거부', request: { ...normal, requestId: randomUUID(),
      path: '/api/notes', route: 'GET /api/notes' }, decision: 'deny', ruleId: 'resource_scope' },
    { name: '깊이가 추가된 허용 경로 위조 거부', request: { ...normal, requestId: randomUUID(),
      path: '/notes/demo/another', route: 'GET /notes/:id' }, decision: 'deny', ruleId: 'resource_scope' },
    { name: '경로와 동작 불일치 거부', request: { ...normal, requestId: randomUUID(),
      method: 'PUT', route: 'GET /notes/:id' }, decision: 'deny', ruleId: 'resource_scope' },
    { name: '미등록 기기 거부', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: false }, decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '주체 식별자 누락 거부', request: { ...normal, requestId: randomUUID(),
      subjectId: '' }, decision: 'deny', ruleId: 'resource_scope' },
    { name: '기기 ID 형식 오류 거부', request: { ...normal, requestId: randomUUID(),
      deviceId: 'not-a-device' }, decision: 'deny', ruleId: 'resource_scope' },

    ...[
      ['POST', '/announcements', 'POST /announcements'],
      ['PUT', `/announcements/${announcementId}`, 'PUT /announcements/:id'],
      ['PATCH', `/announcements/${announcementId}`, 'PATCH /announcements/:id'],
      ['DELETE', `/announcements/${announcementId}`, 'DELETE /announcements/:id']
    ].map(([method, path, route]) => ({
      name: `공지 ${method} 쓰기 기본 거부`,
      request: { ...normal, requestId: randomUUID(), service: 'announcements',
        method, path, route, role: 'instructor' },
      decision: 'deny', ruleId: 'instructor_role_required'
    })),
    { name: '강사 자료 쓰기 기본 거부', request: { ...normal, requestId: randomUUID(),
      service: 'teacher_materials', method: 'PATCH', path: '/teacher-materials/demo',
      route: 'PATCH /teacher-materials/:id' }, decision: 'deny', ruleId: 'instructor_role_required' },

    { name: '클라이언트 헤더를 추가한 요청', request: { ...normal, requestId: randomUUID(),
      headers: { 'x-forwarded-for': '127.0.0.1' } }, decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '불명확한 신호 출처', request: { ...normal, requestId: randomUUID(),
      signals: { ...normal.signals, source: 'x-forwarded-for' } }, decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '지역 정보 누락', request: missingRegion, decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '시각 정보 누락', request: missingHour, decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '행동 정보 누락', request: missingBehavior, decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '지역만 다른 요청은 신규 규칙으로 차단하지 않음', request: { ...normal,
      requestId: randomUUID(), signals: { ...normal.signals, region: 'foreign' } }, decision: 'allow' },
    { name: '대량 열람만 발생한 요청은 결합 신호 없이 신규 규칙으로 차단하지 않음',
      request: { ...normal, requestId: randomUUID(),
        recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }] }, decision: 'allow' },
    { name: '기존 위험 사건은 추가 확인', request: { ...normal, requestId: randomUUID(),
      recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] }, decision: 'step_up' },
    { name: '복합 이상 접속은 추가 확인', request: suspicious, decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '추가 인증 뒤 가상 복합 사건 재판정', request: { ...suspicious,
      requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } }, decision: 'allow' }
  ];

  const results = [];
  for (const item of checks) {
    const output = await decide(item.request);
    const passed = validResponse(item.request, output, ruleIds)
      && output.decision === item.decision
      && (!item.reasonCode || output.reasonCode === item.reasonCode)
      && (!item.ruleId || output.ruleIds.includes(item.ruleId));
    results.push({
      name: item.name, passed, decision: output?.decision, reasonCode: output?.reasonCode
    });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) {
      process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name} · ${item.decision ?? '응답 없음'} · ${item.reasonCode ?? '이유 코드 없음'}\n`);
    }
    process.stdout.write('가상 테스트이며 실제 API 소유자·구역 차단을 측정한 결과는 아닙니다.\n');
    if (results.some((item) => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 테스트 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
