import { createHash, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const noteId = '00000000-0000-4000-8000-000000000001';

function makeRequest(signals, recentEvents, overrides = {}) {
  return {
    schema: 'aleph.decision.v1',
    requestId: randomUUID(),
    classId: 'class_fixture',
    projectId: 'project_fixture',
    subjectId: 'learner_fixture',
    deviceId: 'aaaaaaaaaaaaaaaa',
    service: 'notes',
    method: 'GET',
    path: `/notes/${noteId}`,
    route: 'GET /notes/:id',
    queryLength: 0,
    querySha256: createHash('sha256').update('').digest('hex'),
    at: new Date().toISOString(),
    policyRevision: 1,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents,
    signals,
    ...overrides
  };
}

export function fixtureRequests() {
  return {
    normal: makeRequest({
      source: 'judge_fixture', region: 'local', network: 'usual', hour: 14
    }, []),
    suspicious: makeRequest({
      source: 'judge_fixture', region: 'foreign', network: 'first_seen', hour: 3
    }, [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }])
  };
}

const validResponse = (input, output) => output && typeof output === 'object'
  && Object.keys(output).sort().join(',') === 'decision,reasonCode,requestId,ruleIds,schema'
  && output.schema === 'aleph.decision.v1'
  && output.requestId === input.requestId
  && ['allow', 'deny', 'step_up'].includes(output.decision)
  && typeof output.reasonCode === 'string'
  && Array.isArray(output.ruleIds);

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { normal, suspicious } = fixtureRequests();
    const { decide } = await import('../src/decider.mjs');
    const ordinary = await decide(normal);
    const unusual = await decide(suspicious);
    if (!validResponse(normal, ordinary) || !validResponse(suspicious, unusual)) {
      throw new Error('판정기 응답 형식이 맞지 않습니다.');
    }
    process.stdout.write(`정상 단건 메모 읽기: ${ordinary.decision}\n복합 이상 접속: ${unusual.decision}\n`);
    if (ordinary.decision !== 'allow' || unusual.decision !== 'step_up') {
      throw new Error('정상 단건 읽기는 allow, 복합 이상은 step_up이어야 합니다.');
    }
  } catch (error) {
    process.stderr.write(`가상 사건 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
