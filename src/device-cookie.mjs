import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

const COOKIE_NAME = '__Host-byteback-device';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const HASH_PATTERN = /^[0-9a-f]{64}$/u;
const MAX_AGE_SECONDS = 60 * 60 * 24 * 30;

export function createDeviceCredential() {
  const deviceId = randomUUID();
  const token = randomBytes(32).toString('base64url');
  return { deviceId, token, tokenHash: hashDeviceToken(token) };
}

export function hashDeviceToken(token) {
  return createHash('sha256').update(String(token), 'utf8').digest('hex');
}

export function readDeviceCredential(req) {
  const header = req?.headers?.cookie;
  if (typeof header !== 'string') return null;
  const prefix = COOKIE_NAME + '=';
  const item = header.split(';').map((part) => part.trim()).find((part) => part.startsWith(prefix));
  if (!item) return null;
  const value = item.slice(prefix.length);
  const separator = value.indexOf('.');
  if (separator < 0) return null;
  const deviceId = value.slice(0, separator);
  const token = value.slice(separator + 1);
  if (!UUID_PATTERN.test(deviceId) || !TOKEN_PATTERN.test(token)) return null;
  return { deviceId, token };
}

export function matchesDeviceToken(token, expectedHash) {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)
      || typeof expectedHash !== 'string' || !HASH_PATTERN.test(expectedHash)) return false;
  const actual = Buffer.from(hashDeviceToken(token), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function setDeviceCookie(res, deviceId, token) {
  if (!UUID_PATTERN.test(deviceId) || !TOKEN_PATTERN.test(token)) {
    throw new TypeError('INVALID_DEVICE_CREDENTIAL');
  }
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=${deviceId}.${token}; Path=/; Max-Age=${MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Strict`);
}

export function clearDeviceCookie(res) {
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
}

export const deviceCookieName = COOKIE_NAME;
