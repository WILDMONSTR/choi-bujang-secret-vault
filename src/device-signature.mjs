import { createHash, createPublicKey, verify } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const NONCE = /^[A-Za-z0-9_-]{16,128}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const MAX_CLOCK_SKEW_MS = 60_000;

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function validatePublicJwk(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || value.kty !== 'EC' || value.crv !== 'P-256'
      || typeof value.x !== 'string' || !BASE64URL.test(value.x)
      || typeof value.y !== 'string' || !BASE64URL.test(value.y)
      || Object.hasOwn(value, 'd')
      || Object.keys(value).some((key) => !['kty', 'crv', 'x', 'y', 'ext', 'key_ops'].includes(key))) {
    return null;
  }
  try {
    const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: value.x, y: value.y }, format: 'jwk' });
    return key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
      ? { kty: 'EC', crv: 'P-256', x: value.x, y: value.y }
      : null;
  } catch {
    return null;
  }
}

export function publicKeyFingerprint(jwk) {
  const publicJwk = validatePublicJwk(jwk);
  if (!publicJwk) throw new TypeError('INVALID_PUBLIC_KEY');
  return sha256Hex(JSON.stringify(publicJwk));
}

export function requestBodyText(req) {
  if (Buffer.isBuffer(req?.rawBody)) return req.rawBody.toString('utf8');
  if (typeof req?.rawBody === 'string') return req.rawBody;
  if (typeof req?.body === 'string') return req.body;
  if (req?.body === undefined || req?.body === null) return '';
  return JSON.stringify(req.body);
}

export function canonicalSignedRequest({ deviceId, timestamp, nonce, method, url, bodyText }) {
  const bodyHash = sha256Hex(bodyText);
  return [
    'aleph-device-request-v1',
    deviceId,
    String(timestamp),
    nonce,
    String(method).toUpperCase(),
    url,
    bodyHash
  ].join('\n');
}

export function verifyDeviceRequest(req, publicJwk, now = Date.now()) {
  const headers = req?.headers ?? {};
  const deviceId = headers['x-app-device-id'];
  const timestampText = headers['x-app-timestamp'];
  const nonce = headers['x-app-nonce'];
  const signatureText = headers['x-app-signature'];
  const timestamp = typeof timestampText === 'string' && /^\d{13}$/u.test(timestampText)
    ? Number(timestampText) : NaN;
  const url = typeof req?.url === 'string' ? req.url : '';
  const method = typeof req?.method === 'string' ? req.method.toUpperCase() : '';

  if (typeof deviceId !== 'string' || !UUID.test(deviceId)
      || !Number.isSafeInteger(timestamp) || Math.abs(now - timestamp) > MAX_CLOCK_SKEW_MS
      || typeof nonce !== 'string' || !NONCE.test(nonce)
      || typeof signatureText !== 'string' || !BASE64URL.test(signatureText)
      || !method || !url.startsWith('/') || url.startsWith('//')
      || url.includes('\\r') || url.includes('\\n')) {
    return { valid: false, code: 'INVALID_DEVICE_SIGNATURE' };
  }

  const jwk = validatePublicJwk(publicJwk);
  if (!jwk) return { valid: false, code: 'INVALID_DEVICE_KEY' };

  try {
    const signature = Buffer.from(signatureText, 'base64url');
    if (signature.length !== 64) return { valid: false, code: 'INVALID_DEVICE_SIGNATURE' };
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    const message = canonicalSignedRequest({
      deviceId, timestamp, nonce, method, url, bodyText: requestBodyText(req)
    });
    const valid = verify('sha256', Buffer.from(message, 'utf8'),
      { key, dsaEncoding: 'ieee-p1363' }, signature);
    return valid
      ? { valid: true, deviceId, timestamp, nonce }
      : { valid: false, code: 'INVALID_DEVICE_SIGNATURE' };
  } catch {
    return { valid: false, code: 'INVALID_DEVICE_SIGNATURE' };
  }
}
