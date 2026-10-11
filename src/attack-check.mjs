// Each stage updates this self-check to inspect the current protection boundary.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('이 단계의 공격 점검은 2단계 설정이 필요합니다.');
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
  if (config.sampleMarker !== 'STEP2_PROTECTED') throw new Error('2단계 공개 자료 확인 표시를 확인해 주세요.');

  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let emptyPublicData = false;
  if (response.ok) {
    try {
      const data = await response.json();
      emptyPublicData = data?.sampleMarker === config.sampleMarker
        && Array.isArray(data.notes) && data.notes.length === 0;
    } catch {
      // A non-JSON response is not treated as a verified empty-data response.
    }
  }
  return [{
    attackId: 'anonymous_note_read',
    expected: '비로그인 공개 정적 경로에서 메모 본문이 노출되지 않음',
    observed: emptyPublicData
      ? '공개 data.json의 메모 목록이 비어 있음'
      : `공개 data.json에서 빈 메모 목록을 확인하지 못함 (HTTP ${response.status})`,
  }];
}
