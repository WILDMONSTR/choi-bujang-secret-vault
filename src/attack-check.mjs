// Each stage updates this self-check to inspect the current protection boundary.
// Never return tokens, private keys, real names, or note bodies.
const TEST_ID = '00000000-0000-4000-8000-000000000001';
const READ_METHODS = new Set(['GET', 'HEAD']);

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

  // GET only: this check never changes remote data.
  const staticResponse = await fetch(new URL('/data.json', app), {
    method: 'GET',
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
    cache: 'no-store',
  });
  const staticDataMissing = staticResponse.status === 404 || staticResponse.status === 410;

  // Write-method entries stay in the report as not_run. They are deliberately
  // skipped before fetch(), so this self-check never sends POST, PUT, or DELETE.
  const anonymousProbes = [
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

  const probeResults = [];
  for (const probe of anonymousProbes) {
    if (!READ_METHODS.has(probe.method)) {
      probeResults.push({
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
      headers: { Accept: 'application/json' },
    });

    let deniedWithoutData = response.status === 401 && probe.method === 'HEAD';
    if (response.status === 401 && probe.method === 'GET') {
      try {
        const payload = await response.json();
        deniedWithoutData = payload?.error === 'UNAUTHORIZED'
          && !Object.hasOwn(payload, 'notes')
          && !Object.hasOwn(payload, 'id')
          && !Object.hasOwn(payload, 'body');
      } catch {
        // A malformed response is not a passing denial.
      }
    }

    probeResults.push({
      attackId: probe.attackId,
      expected: probe.expected,
      observed: deniedWithoutData
        ? 'HTTP 401 UNAUTHORIZED without memo data'
        : `Request sent using ${probe.method}; received HTTP ${response.status}; expected HTTP 401 without memo data`,
    });
  }

  return [
    {
      attackId: 'anonymous_static_data_read',
      expected: '/data.json is not present in the public static output',
      observed: staticDataMissing
        ? '/data.json is not found (HTTP 404/410)'
        : `/data.json is still reachable (HTTP ${staticResponse.status})`,
    },
    ...probeResults,
  ];
}
