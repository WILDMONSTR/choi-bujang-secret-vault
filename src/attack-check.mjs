// Each stage updates this self-check to inspect the current protection boundary.
// Never return tokens, private keys, real names, or note bodies.
const TEST_ID = '00000000-0000-4000-8000-000000000001';

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

  const staticResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
  });
  const staticDataMissing = staticResponse.status === 404 || staticResponse.status === 410;

  const anonymousProbes = [
    { path: '/api/notes', method: 'GET' },
    { path: '/api/notes', method: 'POST', body: { title: 'anonymous-test', body: 'must be denied' } },
    { path: '/api/notes/' + TEST_ID, method: 'GET' },
    { path: '/api/notes/' + TEST_ID, method: 'PUT', body: { title: 'anonymous-test', body: 'must be denied' } },
    { path: '/api/notes/' + TEST_ID, method: 'DELETE' },
  ];
  const probeResults = [];
  for (const probe of anonymousProbes) {
    const headers = { Accept: 'application/json' };
    const init = {
      method: probe.method,
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      cache: 'no-store',
      headers,
    };
    if (probe.body) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(probe.body);
    }
    const response = await fetch(new URL(probe.path, app), init);
    let deniedWithoutData = false;
    if (response.status === 401) {
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
      route: probe.method + ' ' + probe.path,
      passed: deniedWithoutData,
      status: response.status,
    });
  }

  const allAnonymousDenied = probeResults.every(result => result.passed);
  const failedRoutes = probeResults.filter(result => !result.passed)
    .map(result => result.route + ' (HTTP ' + result.status + ')');

  return [
    {
      attackId: 'anonymous_static_data_read',
      expected: '/data.json is not present in the public static output',
      observed: staticDataMissing
        ? '/data.json is not found (HTTP 404/410)'
        : `/data.json is still reachable (HTTP ${staticResponse.status})`,
    },
    {
      attackId: 'anonymous_notes_crud',
      expected: 'unauthenticated GET/POST /api/notes and GET/PUT/DELETE /api/notes/:id all return 401 without memo data',
      observed: allAnonymousDenied
        ? 'All five unauthenticated list/create/item requests returned HTTP 401 without memo data'
        : 'Unauthenticated requests not correctly denied: ' + failedRoutes.join('; '),
    },
  ];
}
