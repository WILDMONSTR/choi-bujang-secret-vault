import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import {
  canonicalSignedRequest,
  publicKeyFingerprint,
  validatePublicJwk,
  verifyDeviceRequest
} from '../src/device-signature.mjs';

const deviceId = 'b93c5f7d-1e4b-4556-bf0f-d1b69f7e46fd';
const timestamp = Date.now();
const nonce = 'nonce_abcdefghijklmnopQRSTUV';
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = publicKey.export({ format: 'jwk' });
const body = { title: '가상 메모', body: '테스트 본문' };
const bodyText = JSON.stringify(body);
const url = '/api/notes';
const method = 'POST';

function signedRequest(overrides = {}) {
  const values = { deviceId, timestamp, nonce, method, url, bodyText, ...overrides };
  const message = canonicalSignedRequest(values);
  const signature = sign('sha256', Buffer.from(message, 'utf8'), {
    key: privateKey, dsaEncoding: 'ieee-p1363'
  }).toString('base64url');
  const request = {
    method: values.method,
    url: values.url,
    body: JSON.parse(values.bodyText),
    headers: {
      'x-app-device-id': values.deviceId,
      'x-app-timestamp': String(values.timestamp),
      'x-app-nonce': values.nonce,
      'x-app-signature': signature
    }
  };
  return { request, signature };
}

test('공개키는 P-256 공개 성분만 허용한다', () => {
  assert.ok(validatePublicJwk(jwk));
  assert.equal(validatePublicJwk({ ...jwk, d: 'private-secret' }), null);
  assert.equal(publicKeyFingerprint(jwk).length, 64);
});

test('올바른 서명 요청은 통과한다', () => {
  const { request } = signedRequest();
  assert.equal(verifyDeviceRequest(request, jwk, timestamp).valid, true);
});

test('서명 후 경로가 바뀌면 거부한다', () => {
  const { request } = signedRequest();
  request.url = '/api/notes?owner=other';
  assert.equal(verifyDeviceRequest(request, jwk, timestamp).valid, false);
});

test('서명 후 본문이 바뀌면 거부한다', () => {
  const { request } = signedRequest();
  request.body.body = '변경된 본문';
  assert.equal(verifyDeviceRequest(request, jwk, timestamp).valid, false);
});

test('오래된 서명과 재사용할 수 없는 형식의 nonce를 거부한다', () => {
  const old = signedRequest({ timestamp: timestamp - 120_000 });
  assert.equal(verifyDeviceRequest(old.request, jwk, timestamp).valid, false);
  const invalidNonce = signedRequest({ nonce: 'short' });
  assert.equal(verifyDeviceRequest(invalidNonce.request, jwk, timestamp).valid, false);
});
