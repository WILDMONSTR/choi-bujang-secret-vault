import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const read = (path) => readFile(new URL('../' + path, import.meta.url), 'utf8');

test('12단계 설정과 보호 API 경로가 함께 등록된다', async () => {
  const config = JSON.parse(await read('aleph.config.json'));
  assert.ok(config.step >= 12);
  assert.equal(config.sampleMarker, 'STEP12_RECLAIM_OPERATIONS_ROOM');
  for (const route of [
    'POST /api/devices/revoke',
    'GET /api/stage10/operations-status',
    'POST /api/stage10/decision-check',
    'POST /api/stage10/detection-check',
  ]) assert.ok(config.allowedRoutes.includes(route), route);
});

test('새 기능은 기존 Vercel catch-all 함수 안에서 분기한다', async () => {
  const devices = await read('api/devices/[...action].js');
  const stage10 = await read('api/stage10/[...action].js');
  assert.match(devices, /device-revoke\\.mjs/u);
  assert.match(devices, /revoke\\s*[,\\n}]/u);
  assert.match(stage10, /stage12-operations-status\\.mjs/u);
  assert.match(stage10, /stage12-decision-check\\.mjs/u);
  assert.match(stage10, /stage12-detection-check\\.mjs/u);
  assert.match(stage10, /'operations-status': operationsStatus/u);
  assert.match(stage10, /'decision-check': decisionCheck/u);
  assert.match(stage10, /'detection-check': detectionCheck/u);
});

test('회수는 승인된 다른 기기를 서버에서 재검증하고 DB RPC에 위임한다', async () => {
  const handler = await read('src/api-handlers/device-revoke.mjs');
  assert.match(handler, /requireApprovedDevice/u);
  assert.match(handler, /readDeviceCredential/u);
  assert.match(handler, /CURRENT_DEVICE_REVOCATION_FORBIDDEN/u);
  assert.match(handler, /stage12_revoke_device/u);
  assert.match(handler, /stage12_device_revocation_audit/u);
  assert.doesNotMatch(handler, /req\\.body\\?\\.ownerId/u);
});

test('회수 감사 마이그레이션은 트랜잭션·RLS·서버 전용 RPC를 사용한다', async () => {
  const sql = await read('supabase/migrations/202610150002_stage12_reclaim_operations_room.sql');
  assert.match(sql, /stage12_device_revocation_audit/u);
  assert.match(sql, /enable row level security/iu);
  assert.match(sql, /revoke all on public\\.stage12_device_revocation_audit from public, anon, authenticated/iu);
  assert.match(sql, /security definer/iu);
  assert.match(sql, /for update/iu);
  assert.match(sql, /grant execute on function public\\.stage12_revoke_device/u);
  assert.match(sql, /p_device_id = p_current_device_id/u);
  assert.match(sql, /status = 'revoked'/u);
  assert.doesNotMatch(sql, /cookie|token|content|private key/iu);
});

test('작전실 상태 API는 실제 DB 결과와 기록이 없다는 사실을 분리한다', async () => {
  const source = await read('src/api-handlers/stage12-operations-status.mjs');
  assert.match(source, /requireApprovedDevice/u);
  assert.match(source, /from\\('app_devices'\\)/u);
  assert.match(source, /from\\('stage10_restore_audit'\\)/u);
  assert.match(source, /from\\('stage12_device_revocation_audit'\\)/u);
  assert.match(source, /decisionHistoryAvailable: false/u);
  assert.match(source, /detectionHistoryAvailable: false/u);
  assert.match(source, /resultQueryAvailable: false/u);
  assert.doesNotMatch(source, /\\.select\\([^)]*content|\\.select\\([^)]*body/iu);
});

test('판정·탐지 자기 점검은 학생 모듈을 실제 실행하고 가상 실행이라고 출처를 밝힌다', async () => {
  const decision = await read('src/api-handlers/stage12-decision-check.mjs');
  const detection = await read('src/api-handlers/stage12-detection-check.mjs');
  assert.match(decision, /from '\\.\\.\\/decider\\.mjs'/u);
  assert.match(decision, /await decide\\(item\\.request\\)/u);
  assert.match(decision, /synthetic-contract-fixtures/u);
  assert.match(decision, /RULE_IDS\\.includes\\(rule\\)/u);
  assert.match(detection, /from '\\.\\.\\/detect\\.mjs'/u);
  assert.match(detection, /detect\\(events\\)/u);
  assert.match(detection, /revocationPerformed: false/u);
  assert.match(detection, /synthetic-detection-fixture/u);
});

test('변경 API는 인증 종류와 무관하게 허용된 브라우저 Origin을 요구한다', async () => {
  const source = await read('src/resource-access.mjs');
  assert.match(source, /\\['POST','PUT','PATCH','DELETE'\\]\\.includes\\(req\\.method\\)&&!isTrustedBrowserOrigin\\(req,config\\)/u);
});

test('작전실 UI는 실제 요청 결과를 출력하며 본문을 드러내지 않고 미실행을 기본값으로 둔다', async () => {
  const html = await read('public/index.html');
  const client = await read('public/operations-room.js');
  const worker = await read('public/sw.js');
  assert.match(html, /id="operations-room" hidden/u);
  assert.match(html, /mountOperationsRoom/u);
  assert.match(html, /41종 필수 공세/u);
  assert.match(html, /최종 클리어/u);
  assert.match(client, /credentials:\\s*'omit'/u);
  assert.match(client, /HTTP 401 UNAUTHORIZED/u);
  assert.match(client, /HTTP 404 NOT_FOUND/u);
  assert.match(client, /ZONE_ACCESS_DENIED/u);
  assert.match(client, /미실행/u);
  assert.match(client, /safeResponseSummary/u);
  assert.match(client, /resultQueryAvailable/u);
  assert.match(worker, /operations-room\\.js/u);
  assert.doesNotMatch(client, /innerHTML\\s*=/u);
});

test('빌드는 12단계 회귀 검사를 포함한다', async () => {
  const pkg = JSON.parse(await read('package.json'));
  assert.equal(pkg.scripts['stage12:test'], 'node --test test/stage12.test.mjs');
  assert.match(pkg.scripts.build, /test\\/stage12\\.test\\.mjs/u);
});
