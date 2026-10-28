import assert from 'node:assert/strict';
import test from 'node:test';
import devices from '../api/devices/[...action].js';
import stage10 from '../api/stage10/[...action].js';

async function invoke(handler, method, url, query = {}) {
  const req = { method, url, query, headers: {} };
  const res = {
    headers: {},
    statusCode: 200,
    setHeader(key, value) { this.headers[key] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; }
  };
  await handler(req, res);
  return { status: res.statusCode, error: res.body?.error };
}

test('device catch-all dispatch works when Vercel omits query.action', async () => {
  assert.deepEqual(await invoke(devices, 'GET', '/api/devices/status'),
    { status: 401, error: 'UNAUTHORIZED' });
  for (const route of ['register', 'approve', 'approve-self', 'revoke']) {
    assert.deepEqual(await invoke(devices, 'GET', '/api/devices/' + route),
      { status: 405, error: 'METHOD_NOT_ALLOWED' });
  }
});

test('stage10 catch-all dispatch works without query.action', async () => {
  for (const route of ['memo-restore', 'policy-restore', 'decision-check', 'detection-check']) {
    assert.deepEqual(await invoke(stage10, 'GET', '/api/stage10/' + route),
      { status: 405, error: 'METHOD_NOT_ALLOWED' });
  }
});

test('query-string action spoofing and unknown API paths cannot redirect dispatch', async () => {
  assert.deepEqual(await invoke(devices, 'GET', '/api/devices/not-real?action=status', { action: 'status' }),
    { status: 404, error: 'NOT_FOUND' });
  assert.deepEqual(await invoke(stage10, 'GET', '/api/stage10/not-real?action=decision-check', { action: 'decision-check' }),
    { status: 404, error: 'NOT_FOUND' });
  assert.deepEqual(await invoke(devices, 'GET', '/api/devices/status/another'),
    { status: 404, error: 'NOT_FOUND' });
});
