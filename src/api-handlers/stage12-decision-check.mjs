import { createHash, randomUUID } from 'node:crypto';
import config from '../../aleph.config.json' with { type: 'json' };
import { decide, RULE_IDS } from '../decider.mjs';
import { requireResourceIdentity, sendResourceError } from '../resource-access.mjs';
import { requireApprovedDevice } from '../require-approved-device.mjs';

function fixture(overrides = {}) {
  return {
    schema: 'aleph.decision.v1',
    requestId: randomUUID(),
    classId: 'stage12-fixture-class',
    projectId: 'stage12-fixture-project',
    subjectId: 'synthetic-subject-only',
    deviceId: 'aaaaaaaaaaaaaaaa',
    service: 'notes',
    method: 'GET',
    path: '/notes/demo',
    route: 'GET /notes/:id',
    queryLength: 0,
    querySha256: createHash('sha256').update('', 'utf8').digest('hex'),
    at: new Date().toISOString(),
    policyRevision: 12,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [],
    signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
    ...overrides,
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;
  if (!await requireApprovedDevice(req, res, auth)) return;

  try {
    const checks = [
      { id: 'student-decision-normal-fixture', expected: 'allow', request: fixture() },
      {
        id: 'student-decision-suspicious-fixture',
        expected: 'step_up',
        request: fixture({
          signals: { source: 'judge_fixture', region: 'foreign', network: 'first_seen', hour: 3 },
          recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }],
        }),
      },
      {
        id: 'student-decision-unregistered-device',
        expected: 'deny',
        request: fixture({ deviceRegistered: false }),
      },
      {
        id: 'student-decision-out-of-scope-route',
        expected: 'deny',
        request: fixture({ path: '/notes/demo/extra', route: 'GET /notes/:id' }),
      },
    ];

    const results = [];
    for (const item of checks) {
      const output = await decide(item.request);
      const validShape = output && Object.keys(output).sort().join(',')
        === 'decision,reasonCode,requestId,ruleIds,schema'
        && output.schema === 'aleph.decision.v1'
        && output.requestId === item.request.requestId
        && ['allow', 'deny', 'step_up'].includes(output.decision)
        && typeof output.reasonCode === 'string'
        && Array.isArray(output.ruleIds)
        && output.ruleIds.every((rule) => RULE_IDS.includes(rule));
      results.push({
        id: item.id,
        expected: item.expected,
        actual: output?.decision ?? 'no_response',
        reasonCode: output?.reasonCode ?? null,
        ruleIds: Array.isArray(output?.ruleIds) ? output.ruleIds : [],
        passed: validShape && output.decision === item.expected,
      });
    }

    return res.status(200).json({
      source: { owner: 'student', file: 'src/decider.mjs', revision: process.env.VERCEL_GIT_COMMIT_SHA || null },
      mode: 'synthetic-contract-fixtures',
      executedAt: new Date().toISOString(),
      allPassed: results.every((item) => item.passed),
      executedCount: results.length,
      results,
      note: '실제 학생 판정기 코드의 가상 요청 결과입니다. 외부 심판의 41종 공격 결과나 실사용자 판정 이력이 아닙니다.',
    });
  } catch {
    return sendResourceError(res, 500, 'STUDENT_DECIDER_CHECK_FAILED');
  }
}
