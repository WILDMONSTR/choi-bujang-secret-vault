import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('설정은 11단계 이상이며 서버 확인용 장치 상태 경로를 등록한다', async () => {
  const config = JSON.parse(await read('aleph.config.json'));
  assert.ok(Number.isInteger(config.step) && config.step >= 11);
  for (const route of [
    'POST /api/devices/register', 'GET /api/devices/status', 'GET /api/devices',
    'POST /api/devices/approve', 'POST /api/devices/approve-self'
  ]) assert.ok(config.allowedRoutes.includes(route), route);
});

test('보호 자료 API는 서버의 승인 기기 확인을 거친다', async () => {
  for (const path of [
    'api/notes.js', 'api/notes/[id].js',
    'api/announcements.js', 'api/announcements/[id].js'
  ]) {
    const source = await read(path);
    assert.match(source, /requireApprovedDevice/u, path);
  }
  const recovery = await read('src/stage10-recovery-api.mjs');
  assert.match(recovery, /requireApprovedDevice/u);
  const verifier = await read('src/require-approved-device.mjs');
  assert.match(verifier, /device_cookie_sha256/u);
  assert.match(verifier, /status !== 'approved'/u);
  assert.match(verifier, /matchesDeviceToken/u);
  assert.doesNotMatch(verifier, /verifyDeviceRequest|app_device_request_nonces/u);
});

test('기기 등록·승인은 서버가 발급한 쿠키와 비밀번호 재확인을 사용한다', async () => {
  const register = await read('src/api-handlers/device-register.mjs');
  assert.match(register, /status:\s*'pending'/u);
  assert.match(register, /device_cookie_sha256/u);
  assert.match(register, /setDeviceCookie/u);
  assert.doesNotMatch(register, /publicJwk|privateKey|crypto\.subtle/u);

  const approve = await read('src/api-handlers/device-approve-self.mjs');
  assert.match(approve, /signInWithPassword/u);
  assert.match(approve, /findDeviceForSession/u);
  assert.doesNotMatch(approve, /body\?\.deviceId/u);
  const next = await read('src/api-handlers/device-approve.mjs');
  assert.match(next, /requireApprovedDevice/u);
});

test('브라우저 번들에는 개인키 생성·서명·지속 저장 로직이 없다', async () => {
  const client = await read('public/device-client.js');
  assert.doesNotMatch(client, /indexedDB|localStorage|sessionStorage|crypto\.subtle|privateKey|publicJwk|x-app-signature/iu);
  assert.match(client, /credentials:\s*'same-origin'/u);
  assert.match(client, /api\/devices\/status/u);
});

test('기존 자료실은 서버가 승인했다고 확인한 뒤에만 연다', async () => {
  const html = await read('public/index.html');
  assert.match(html, /notesWorkspace\.hidden = true/u);
  assert.match(html, /status\?\.approved === true/u);
  assert.match(html, /approvedDeviceAccess/u);
  assert.match(html, /await initializeDeviceAccess\(result\)/u);
  const confirmedAt = html.indexOf("status?.registered === true && status?.approved === true && status?.status === 'approved'");
  const loadAt = html.indexOf('await loadNotesForSession(session)', confirmedAt);
  assert.ok(confirmedAt >= 0 && loadAt > confirmedAt, '자료 요청은 승인 응답 분기 안에서 호출되어야 함');
  assert.doesNotMatch(html, /개인키는 이 브라우저의 로컬 저장소에 보관/u);
});

test('설치형 앱은 앱 셸만 캐시하고 API 응답을 캐시하지 않는다', async () => {
  const manifest = JSON.parse(await read('public/manifest.webmanifest'));
  assert.equal(manifest.display, 'standalone');
  assert.ok(manifest.icons.some((icon) => icon.src === '/app-icon.svg'));
  const worker = await read('public/sw.js');
  assert.match(worker, /url\.pathname\.startsWith\('\/api\/'\)/u);
  assert.match(worker, /SHELL\.includes\(url\.pathname\)/u);
  const html = await read('public/index.html');
  assert.match(html, /manifest\.webmanifest/u);
  assert.match(html, /serviceWorker\.register\('\/sw\.js'\)/u);
});
