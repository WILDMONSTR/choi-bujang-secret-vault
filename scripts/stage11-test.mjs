import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('설정은 11단계 이상이며 장치 승인 경로를 등록한다', async () => {
  const config = JSON.parse(await read('aleph.config.json'));
  assert.ok(Number.isInteger(config.step) && config.step >= 11);
  for (const route of [
    'POST /api/devices/register', 'GET /api/devices',
    'POST /api/devices/approve', 'POST /api/devices/approve-self'
  ]) assert.ok(config.allowedRoutes.includes(route), route);
});

test('보호 자료 API는 승인된 기기 서명 검사를 거친다', async () => {
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
  assert.match(verifier, /device\.status !== 'approved'/u);
  assert.match(verifier, /app_device_request_nonces/u);
  assert.match(verifier, /DEVICE_REQUEST_REPLAYED/u);
});

test('기기 등록은 pending으로 시작하고 첫 승인은 비밀번호를 다시 확인한다', async () => {
  const register = await read('api/devices/register.js');
  assert.match(register, /status: 'pending'/u);
  const approve = await read('api/devices/approve-self.js');
  assert.match(approve, /signInWithPassword/u);
  assert.match(approve, /signedIn\?\.user\?\.id !== auth\.identity\.userId/u);
  const next = await read('api/devices/approve.js');
  assert.match(next, /requireApprovedDevice/u);
});

test('서명 계약은 경로·메서드·본문 해시·시간·nonce를 묶는다', async () => {
  const source = await read('src/device-signature.mjs');
  for (const field of [
    'aleph-device-request-v1', 'method', 'url', 'bodyHash',
    'timestamp', 'nonce', 'verifyDeviceRequest'
  ]) assert.ok(source.includes(field), field);
  const decider = await read('src/decider.mjs');
  assert.doesNotMatch(decider, /request\.role|request\.identity|request\.device\./u);
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
