import { createHash } from 'node:crypto';

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

    const url = new URL(probe.path, app);
    let response;
    try {
      response = await fetch(url, {
        method: probe.method,
        // Preserve received 3xx statuses as evidence rather than turning them into fetch errors.
        redirect: 'manual',
        signal: AbortSignal.timeout(10000),
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        // The judge runner recognizes this fetch metadata; it is not an HTTP header.
        alephEvidence: { caseId: probe.attackId, requestKey: 'read' },
      });
    } catch {
      // A request was attempted but yielded no HTTP response; do not mislabel it as unrequested.
      results.push({
        attackId: probe.attackId,
        expected: probe.expected,
        observed: 'no_http_response',
      });
      continue;
    }

    // Preserve status as soon as fetch returns a Response. Body consumption may fail after
    // headers have arrived; that must never erase the HTTP status or turn this into not_run.
    const urlSha256 = createHash('sha256').update(url.href).digest('hex');
    let bodyBytes = 'unavailable';
    try {
      bodyBytes = (await response.arrayBuffer()).byteLength;
    } catch {
      // The response status is still real; only the body length is unavailable.
    }

    // Record only response metadata, never the response body itself.
    results.push({
      attackId: probe.attackId,
      expected: probe.expected,
      observed: `HTTP ${response.status}; method=${probe.method}; urlSha256=${urlSha256}; bodyBytes=${bodyBytes}`,
    });
  }

  return results;
}
