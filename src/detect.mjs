// 9단계: 동일 주체의 동일 가상 기기에서 과도한 자료 조회를 탐지해 회수 제안을 반환합니다.
// 운영 반 엔진이 검증한 사건만 전달해야 합니다. 여기서는 실제 권한을 회수하지 않습니다.
const READ_LIMIT = 120;
const WINDOW_MS = 10 * 60 * 1000;
const EVENT_KEYS = ['at', 'deviceId', 'identity', 'method'].sort().join(',');
const IDENTITY_KEYS = ['sub'].join(',');
const DEVICE_ID_PATTERN = /^[0-9a-f]{16}$/u;

function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)
      || Object.keys(event).sort().join(',') !== EVENT_KEYS
      || typeof event.at !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(event.at)
      || !Number.isFinite(Date.parse(event.at))
      || new Date(Date.parse(event.at)).toISOString() !== event.at
      || typeof event.method !== 'string' || !/^[A-Z]{3,10}$/u.test(event.method)
      || typeof event.deviceId !== 'string' || !DEVICE_ID_PATTERN.test(event.deviceId)
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
    subject: event.identity.sub,
    deviceId: event.deviceId,
  };
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  // Counts are isolated by both verified subject and verified virtual device.
  const readsBySubject = new Map();
  for (const rawEvent of events) {
    const event = readEvent(rawEvent);
    if (event.method !== 'GET') continue;
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
        // Keep one global proposal: the first threshold crossing only.
        break;
      }
    }
  }

  if (!earliest) return { action: 'observe' };
  return {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    target: { kind: 'virtual_device', deviceId: earliest.deviceId },
  };
}
