import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(request, response, ruleIds) {
  return response && typeof response === 'object' && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === RESPONSE_KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && typeof response.reasonCode === 'string'
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(id => ruleIds.includes(id));
}

// Local practice only. The class engine and the server judge validate live requests separately.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !Array.isArray(ruleIds)
      || !ruleIds.includes('device_registered') || !ruleIds.includes('signal_provenance')) {
    throw new Error('6단계 device_registered와 7단계 signal_provenance 규칙을 먼저 구현하고 RULE_IDS에 적어 주세요.');
  }
  const { normal, suspicious } = fixtureRequests();
  const checks = [
    { name: '등록 기기의 정상 요청', request: normal, decision: 'allow' },
    { name: '미등록 기기의 가상 요청', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: false }, decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '기기 등록 값이 없는 가상 요청', request: (() => {
      const request = { ...normal, requestId: randomUUID() };
      delete request.deviceRegistered;
      return request;
    })(), decision: 'deny', reasonCode: 'device_not_registered' },
  ];
  const missingRegion = { ...normal, requestId: randomUUID(),
    signals: { ...normal.signals } };
  delete missingRegion.signals.region;
  const missingHour = { ...normal, requestId: randomUUID(),
    signals: { ...normal.signals, hour: null } };
  const missingBehavior = { ...normal, requestId: randomUUID() };
  delete missingBehavior.recentEvents;
  checks.push(
    { name: '클라이언트 헤더 출처는 신뢰하지 않음', request: { ...normal,
      requestId: randomUUID(), headers: { 'x-forwarded-for': '127.0.0.1' } },
      decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '출처가 불명확한 신호', request: { ...normal, requestId: randomUUID(),
      signals: { ...normal.signals, source: 'x-forwarded-for' } },
      decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '지역 정보 누락', request: missingRegion,
      decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '시각 정보 누락', request: missingHour,
      decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '행동 정보 누락', request: missingBehavior,
      decision: 'step_up', reasonCode: 'step_up_required' },
  );
  checks.push(
    { name: '지역만 다른 정상 시각·기존 네트워크', request: { ...normal,
      requestId: randomUUID(), signals: { ...normal.signals, region: 'foreign' } },
      decision: 'allow', reasonCode: 'approved' },
    { name: '대량 읽기만 있고 시각·네트워크는 평소와 같음', request: { ...normal,
      requestId: randomUUID(), recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }] },
      decision: 'allow', reasonCode: 'approved' },
    { name: '시각·네트워크 변화와 대량 읽기가 결합됨', request: suspicious,
      decision: 'step_up', reasonCode: 'step_up_required', ruleId: 'unusual_access_context' },
    { name: '기존 대량 위험 사건 규칙 유지', request: { ...normal,
      requestId: randomUUID(), recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] },
      decision: 'step_up', reasonCode: 'step_up_required' },
  );
  if (ruleIds.includes('step_up_required')) {
    checks.push(
      { name: '복합 이상 접속', request: suspicious, decision: 'step_up',
        reasonCode: 'step_up_required', ruleId: 'unusual_access_context' },
      { name: '다시 확인한 복합 이상 접속', request: { ...suspicious,
        requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'allow' },
    );
  }
  const results = [];
  for (const item of checks) {
    const response = await decide(item.request);
    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && (!item.reasonCode || response.reasonCode === item.reasonCode)
      && (!item.ruleId || response.ruleIds.includes(item.ruleId));
    results.push({ name: item.name, passed: valid, decision: response?.decision, reasonCode: response?.reasonCode });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name} · ${item.decision ?? '응답 없음'} · ${item.reasonCode ?? '이유 코드 없음'}\n`);
    process.stdout.write('이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
