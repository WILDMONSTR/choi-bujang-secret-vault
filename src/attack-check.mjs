// Each stage updates this self-check to inspect the current protection boundary.
// Never return tokens, private keys, real names, or note bodies.
const EXPECTED_TITLES = ['과제', '포트폴리오', '아침 리추얼', '훈련 행정 자료'];

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

  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  let hasFourNotes = false;
  if (apiResponse.ok) {
    try {
      const payload = await apiResponse.json();
      hasFourNotes = Array.isArray(payload?.notes) && payload.notes.length === 4
        && payload.notes.every((note, index) => note?.title === EXPECTED_TITLES[index]
          && typeof note.content === 'string');
    } catch {
      // A malformed response is a failed check, not a successful API response.
    }
  }

  return [
    {
      attackId: 'anonymous_static_data_read',
      expected: '/data.json is not present in the public static output',
      observed: staticDataMissing
        ? '/data.json is not found (HTTP 404/410)'
        : `/data.json is still reachable (HTTP ${staticResponse.status})`,
    },
    {
      attackId: 'public_notes_api',
      expected: 'the public API returns only the four intended virtual notes; unauthenticated access is a known limitation',
      observed: hasFourNotes
        ? '/api/notes returned four virtual notes without caller authentication; the endpoint remains publicly callable'
        : `/api/notes did not return the expected four-note response (HTTP ${apiResponse.status})`,
    },
  ];
}
