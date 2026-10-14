import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  clearDeviceCookie, createDeviceCredential, hashDeviceToken,
  matchesDeviceToken, readDeviceCredential, setDeviceCookie
} from '../src/device-cookie.mjs';

test('기기 쿠키 토큰은 서버에서 만들고 DB에는 SHA-256만 저장한다', () => {
  const credential = createDeviceCredential();
  assert.match(credential.deviceId, /^[0-9a-f-]{36}$/u);
  assert.match(credential.token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(credential.tokenHash, hashDeviceToken(credential.token));
  assert.equal(matchesDeviceToken(credential.token, credential.tokenHash), true);
  assert.equal(matchesDeviceToken('A'.repeat(43), credential.tokenHash), false);
});

test('기기 세션 쿠키는 HttpOnly, Secure, SameSite=Strict이다', () => {
  const credential = createDeviceCredential();
  const headers = new Map();
  setDeviceCookie({ setHeader: (key, value) => headers.set(key, value) },
    credential.deviceId, credential.token);
  const value = headers.get('Set-Cookie');
  assert.match(value, /HttpOnly/u);
  assert.match(value, /Secure/u);
  assert.match(value, /SameSite=Strict/u);
  assert.match(value, /Path=\//u);
  assert.doesNotMatch(value, /Domain=/u);

  const parsed = readDeviceCredential({ headers: { cookie: value.split(';')[0] } });
  assert.deepEqual(parsed, { deviceId: credential.deviceId, token: credential.token });
});

test('유효하지 않은 쿠키는 장치 자격 증명으로 받아들이지 않는다', () => {
  assert.equal(readDeviceCredential({ headers: { cookie: '__Host-byteback-device=bad' } }), null);
  const headers = new Map();
  clearDeviceCookie({ setHeader: (key, value) => headers.set(key, value) });
  assert.match(headers.get('Set-Cookie'), /Max-Age=0/u);
});
