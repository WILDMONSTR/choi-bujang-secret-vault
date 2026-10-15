// Each stage updates this self-check to inspect the current protection boundary.
// Never return tokens, private keys, real names, or note bodies.
const TEST_ID = '00000000-0000-4000-8000-000000000001';
const READ_METHODS = new Set(['GET', 'HEAD']);
const ATTACK_ID_HEADER = 'x-aleph-attack-id';

export async function runAttackChecks(config) {
  if (!Number.isInteger(config.step) || config.step < 2 || config.step > 12) {
    throw new Error('이 단계의 공격 점검은 2~12단계 설정이 필요합니다.');
  }

  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const probeDefinitions = [
    {
      attackId: 'anonymous_static_data_read',
      path: '/data.json',
      method: 'GET',
      expected: '/data.json is not present in the public static output',
    },
    {
      attackId: 'anonymous_notes_list',
      path: '/api/notes',
      method: 'GET',
      expected: 'Unauthenticated GET /api/notes returns HTTP 401 without memo data',
    },
    {
      attackId: 'anonymous_notes_create',
      path: '/api/notes',
      method: 'POST',
      expected: 'Unauthenticated POST /api/notes is denied without creating a memo',
    },
    {
      attackId: 'anonymous_note_read',
      path: '/api/notes/' + TEST_ID,
      method: 'GET',
      expected: 'Unauthenticated GET /api/notes/:id returns HTTP 401 without memo data',
    },
    {
      attackId: 'anonymous_note_update',
      path: '/api/notes/' + TEST_ID,
      method: 'PUT',
      expected: 'Unauthenticated PUT /api/notes/:id is denied without changing a memo',
    },
    {
      attackId: 'anonymous_note_delete',
      path: '/api/notes/' + TEST_ID,
      method: 'DELETE',
      expected: 'Unauthenticated DELETE /api/notes/:id is denied without deleting a memo',
    },
  ];

  const results = [];
  for (const probe of probeDefinitions) {
    // Do not even construct/send a request for write methods in the isolated runner.
    if (!READ_METHODS.has(probe.method)) {
      results.push({
        attackId: probe.attackId,
        expected: probe.expected,
        observed: 'not_run',
      });
      continue;
    }

    const response = await fetch(new URL(probe.path, app), {
      method: probe.method,
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      cache: 'no-store',
      headers: { Accept: 'application/json', [ATTACK_ID_HEADER]: probe.attackId },
    });

    // observed contains only the HTTP status actually returned by the server.
    results.push({
      attackId: probe.attackId,
      expected: probe.expected,
      observed: `HTTP ${response.status}`,
    });
  }

  return results;
}
