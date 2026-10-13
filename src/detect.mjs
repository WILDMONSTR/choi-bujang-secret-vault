// 9단계: 확인된 새 네트워크에서 발생한 조회 폭주만 회수 제안 후보로 표시합니다.
// 운영 반 엔진이 검증한 사건만 전달해야 합니다. 여기서는 실제 권한을 회수하지 않습니다.
const READ_LIMIT = 120;
const WINDOW_MS = 10 * 60 * 1000;
const REQUIRED_EVENT_KEYS = ['at', 'deviceId', 'identity', 'method', 'network'].sort();
const ALLOWED_EVENT_KEYS = [...REQUIRED_EVENT_KEYS, 'region'].sort();
const IDENTITY_KEYS = ['sub'].join(',');
const DEVICE_ID_PATTERN = /^[0-9a-f]{16}$/u;
const VALID_NETWORK_STATES = new Set(['usual', 'first_seen', 'unknown']);

function readEvent(event) {
  const keys = event && typeof event === 'object' && !Array.isArray(event)
    ? Object.keys(event).sort() : [];
  const hasRequiredKeys = REQUIRED_EVENT_KEYS.every((key) => keys.includes(key));
  const hasOnlyAllowedKeys = keys.every((key) => ALLOWED_EVENT_KEYS.includes(key));

  if (!event || typeof event !== 'object' || Array.isArray(event)
      || !hasRequiredKeys || !hasOnlyAllowedKeys
      || typeof event.at !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(event.at)
      || !Number.isFinite(Date.parse(event.at))
      || new Date(Date.parse(event.at)).toISOString() !== event.at
      || typeof event.method !== 'string' || !/^[A-Z]{3,10}$/u.test(event.method)
      || typeof event.deviceId !== 'string' || !DEVICE_ID_PATTERN.test(event.deviceId)
      || !VALID_NETWORK_STATES.has(event.network)
      || (Object.hasOwn(event, 'region')
        && (typeof event.region !== 'string' || event.region.trim() !== event.region
          || event.region.length === 0 || event.region.length > 64))
      || !event.identity || typeof event.identity !== 'object' || Array.isArray(event.identity)
      || Object.keys(event.identity).sort().join(',') !== IDENTITY_KEYS
      || typeof event.identity.sub !== 'string'
      || event.identity.sub.trim() !== event.identity.sub
      || event.identity.sub.length === 0 || event.identity.sub.length > 256) {
    throw new TypeError('invalid_detection_event');
  }
  return {
    at: Date.parse(event.at),
    method: event.method,
    network: event.network,
    subject: event.identity.sub,
    deviceId: event.deviceId,
  };
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  // Region is contextual only. The detector needs both first-seen network and a
  // high-volume GET window on that same network, for the same subject/device.
  const readsBySubject = new Map();
  for (const rawEvent of events) {
    const event = readEvent(rawEvent);
    if (event.method !== 'GET' || event.network !== 'first_seen') continue;
    if (!readsBySubject.has(event.subject)) readsBySubject.set(event.subject, new Map());
    const devices = readsBySubject.get(event.subject);
    if (!devices.has(event.deviceId)) devices.set(event.deviceId, []);
    devices.get(event.deviceId).push(event.at);
  }

  let earliest = null;
  for (const [subject, devices] of readsBySubject) {
    for (const [deviceId, timestamps] of devices) {
      timestamps.sort((a, b) => a - b);
      let left = 0;
      for (let right = 0; right < timestamps.length; right += 1) {
        while (timestamps[right] - timestamps[left] > WINDOW_MS) left += 1;
        if (right - left + 1 <= READ_LIMIT) continue;

        const candidate = { at: timestamps[right], subject, deviceId };
        if (!earliest || candidate.at < earliest.at
            || (candidate.at === earliest.at && candidate.deviceId < earliest.deviceId)
            || (candidate.at === earliest.at && candidate.deviceId === earliest.deviceId
              && candidate.subject < earliest.subject)) {
          earliest = candidate;
        }
        // Propose for only one device: the earliest composite threshold crossing.
        break;
      }
    }
  }

  if (!earliest) return { action: 'observe' };
  return {
    action: 'propose_revocation',
    reasonCode: 'unusual_network_burst_read',
    target: { kind: 'virtual_device', deviceId: earliest.deviceId },
  };
}
