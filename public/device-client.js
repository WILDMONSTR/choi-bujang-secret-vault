const DB_NAME = 'byte-back-device-v1';
const STORE = 'keys';
const KEY_ID = 'current';
const encoder = new TextEncoder();

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('DEVICE_KEY_STORAGE_UNAVAILABLE'));
  });
}

async function readKeyRecord() {
  const db = await openKeyDb();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(STORE, 'readonly').objectStore(STORE).get(KEY_ID);
      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(new Error('DEVICE_KEY_STORAGE_UNAVAILABLE'));
    });
  } finally {
    db.close();
  }
}

async function writeKeyRecord(value) {
  const db = await openKeyDb();
  try {
    await new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE, 'readwrite');
      transaction.objectStore(STORE).put(value, KEY_ID);
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(new Error('DEVICE_KEY_STORAGE_UNAVAILABLE'));
      transaction.onabort = () => reject(new Error('DEVICE_KEY_STORAGE_UNAVAILABLE'));
    });
  } finally {
    db.close();
  }
}

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(value) {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
}

function randomNonce() {
  return base64Url(crypto.getRandomValues(new Uint8Array(24)));
}

async function getOrCreateDevice() {
  if (!globalThis.crypto?.subtle || !globalThis.indexedDB) {
    throw new Error('DEVICE_CRYPTO_UNAVAILABLE');
  }
  const current = await readKeyRecord();
  if (current?.deviceId && current?.privateKey && current?.publicJwk) return current;

  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const record = {
    deviceId: crypto.randomUUID(),
    privateKey: pair.privateKey,
    publicJwk: { kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y },
    label: (navigator.userAgentData?.platform || navigator.platform || '이 브라우저').slice(0, 80)
  };
  await writeKeyRecord(record);
  return record;
}

export async function registerCurrentDevice() {
  const device = await getOrCreateDevice();
  const bodyText = JSON.stringify({
    deviceId: device.deviceId,
    publicJwk: device.publicJwk,
    label: device.label
  });
  const response = await fetch('/api/devices/register', {
    method: 'POST',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: bodyText
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error || 'DEVICE_REGISTRATION_FAILED');
  return data;
}

export async function approveCurrentDevice(email, password) {
  const device = await getOrCreateDevice();
  const response = await fetch('/api/devices/approve-self', {
    method: 'POST',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: device.deviceId, email, password })
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error || 'DEVICE_APPROVAL_FAILED');
  return data;
}

export async function signedDeviceRequest(path, method = 'GET', payload) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')
      || path.includes('#') || path.includes('\\r') || path.includes('\\n')) {
    throw new Error('INVALID_SIGNED_PATH');
  }
  const device = await getOrCreateDevice();
  const timestamp = String(Date.now());
  const nonce = randomNonce();
  const verb = method.toUpperCase();
  const bodyText = payload === undefined ? '' : JSON.stringify(payload);
  const bodyHash = await sha256Hex(bodyText);
  const canonical = [
    'aleph-device-request-v1', device.deviceId, timestamp, nonce,
    verb, path, bodyHash
  ].join('\n');
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, device.privateKey, encoder.encode(canonical)
  ));
  const headers = {
    Accept: 'application/json',
    'X-App-Device-Id': device.deviceId,
    'X-App-Timestamp': timestamp,
    'X-App-Nonce': nonce,
    'X-App-Signature': base64Url(signature)
  };
  const options = { method: verb, cache: 'no-store', credentials: 'same-origin', headers };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    options.body = bodyText;
  }
  const response = await fetch(path, options);
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error || ('HTTP_' + response.status));
  return data;
}

export async function currentDeviceId() {
  const device = await readKeyRecord();
  return device?.deviceId ?? null;
}
