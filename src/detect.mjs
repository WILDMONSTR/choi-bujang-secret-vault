// 9단계: 평소와 다른 네트워크와 다량 조회가 함께 나타난 가상 기기만 회수 제안 대상으로 표시합니다.
// 운영 반 엔진이 검증한 사건만 전달해야 합니다. 실제 권한 회수는 수행하지 않습니다.
const READ_LIMIT = 120;
const WINDOW_MS = 10 * 60 * 1000;
const RISK_WINDOW_SECONDS = 300;
const RISK_COUNT_THRESHOLD = 10;

const ALLOWED_EVENT_KEYS = new Set([
  'at', 'deviceId', 'identity', 'method', 'network', 'region',
  'signals', 'recentEvents', 'subjectId',
  // Fields from the established aleph.decision.v1 request contract.
  'schema', 'requestId', 'classId', 'projectId', 'service', 'path', 'route',
  'queryLength', 'querySha256', 'policyRevision', 'deviceRegistered', 'stepUp',
]);
const IDENTITY_KEYS = 'sub';
const SIGNAL_KEYS = 'hour,network,region,source';
const RECENT_EVENT_KEYS = 'ageSeconds,count,kind';
const DEVICE_ID_PATTERN = /^[0-9a-f]{16}$/u;
const NETWORK_STATES = new Set(['usual', 'first_seen', 'unknown']);

function readRecentEvents(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 12) {
    throw new TypeError('invalid_detection_event');
  }
  for (const event of value) {
    if (!event || typeof event !== 'object' || Array.isArray(event)
        || Object.keys(event).sort().join(',') !== RECENT_EVENT_KEYS
        || typeof event.kind !== 'string' || !/^[a-z][a-z0-9_-]{0,63}$/u.test(event.kind)
        || !Number.isFinite(event.ageSeconds) || event.ageSeconds < 0
        || !Number.isSafeInteger(event.count) || event.count < 0) {
      throw new TypeError('invalid_detection_event');
    }
  }
  return value;
}

function readNetwork(event) {
  let nestedNetwork;
  if (event.signals !== undefined) {
    const signals = event.signals;
    if (!signals || typeof signals !== 'object' || Array.isArray(signals)
        || Object.keys(signals).sort().join(',') !== SIGNAL_KEYS
        || typeof signals.source !== 'string'
        || typeof signals.region !== 'string'
        || !NETWORK_STATES.has(signals.network)
        || !(signals.hour === null || (Number.isInteger(signals.hour)
          && signals.hour >= 0 && signals.hour <= 23))) {
      throw new TypeError('invalid_detection_event');
    }
    nestedNetwork = signals.network;
  }

  const directNetwork = event.network;
  if (directNetwork !== undefined && !NETWORK_STATES.has(directNetwork)) {
    throw new TypeError('invalid_detection_event');
  }
  if (directNetwork !== undefined && nestedNetwork !== undefined
      && directNetwork !== nestedNetwork) {
    throw new TypeError('invalid_detection_event');
  }
  // Old, otherwise-valid observation records may lack telemetry. Unknown is
  // not treated as a new network, so missing evidence cannot trigger a proposal.
  return directNetwork ?? nestedNetwork ?? 'unknown';
}

function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)
      || Object.keys(event).some((key) => !ALLOWED_EVENT_KEYS.has(key))
      || typeof event.at !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(event.at)
      || !Number.isFinite(Date.parse(event.at))
      || new Date(Date.parse(event.at)).toISOString() !== event.at
      || typeof event.method !== 'string' || !/^[A-Z]{3,10}$/u.test(event.method)
      || typeof event.deviceId !== 'string' || !DEVICE_ID_PATTERN.test(event.deviceId)) {
    throw new TypeError('invalid_detection_event');
  }

  let subject;
  if (event.identity !== undefined) {
    if (!event.identity || typeof event.identity !== 'object' || Array.isArray(event.identity)
        || Object.keys(event.identity).sort().join(',') !== IDENTITY_KEYS
        || typeof event.identity.sub !== 'string'
        || event.identity.sub.trim() !== event.identity.sub
        || event.identity.sub.length === 0 || event.identity.sub.length > 256) {
      throw new TypeError('invalid_detection_event');
    }
    subject = event.identity.sub;
  }
  if (event.subjectId !== undefined) {
    if (typeof event.subjectId !== 'string' || event.subjectId.trim() !== event.subjectId
        || event.subjectId.length === 0 || event.subjectId.length > 256
        || (subject !== undefined && subject !== event.subjectId)) {
      throw new TypeError('invalid_detection_event');
    }
    subject = event.subjectId;
  }
  if (subject === undefined) throw new TypeError('invalid_detection_event');

  if (event.region !== undefined && (typeof event.region !== 'string'
      || event.region.trim() !== event.region || event.region.length > 64)) {
    throw new TypeError('invalid_detection_event');
  }

  return {
    at: Date.parse(event.at),
    method: event.method,
    network: readNetwork(event),
    recentEvents: readRecentEvents(event.recentEvents),
    subject,
    deviceId: event.deviceId,
  };
}

function hasRecentBulkRead(event) {
  return event.recentEvents.some((item) =>
    item.kind === 'bulk_read'
      && item.ageSeconds <= RISK_WINDOW_SECONDS
      && item.count >= RISK_COUNT_THRESHOLD);
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  const candidates = [];

  for (const rawEvent of events) {
    const event = readEvent(rawEvent);
    if (event.method !== 'GET' || event.network !== 'first_seen') continue;

    // Support the established decision-request format: an event can carry a
    // recentEvents bulk_read signal instead of requiring 121 separate records.
    if (hasRecentBulkRead(event)) {
      candidates.push({ at: event.at, subject: event.subject, deviceId: event.deviceId });
    }

    if (!readsBySubject.has(event.subject)) readsBySubject.set(event.subject, new Map());
    const devices = readsBySubject.get(event.subject);
    if (!devices.has(event.deviceId)) devices.set(event.deviceId, []);
    devices.get(event.deviceId).push(event.at);
  }

  // Keep the 9-stage rolling-window contract too: repeated GET requests from
  // the same subject/device on a first-seen network must exceed 120 per 10 minutes.
  for (const [subject, devices] of readsBySubject) {
    for (const [deviceId, timestamps] of devices) {
      timestamps.sort((a, b) => a - b);
      let left = 0;
      for (let right = 0; right < timestamps.length; right += 1) {
        while (timestamps[right] - timestamps[left] > WINDOW_MS) left += 1;
        if (right - left + 1 <= READ_LIMIT) continue;
        candidates.push({ at: timestamps[right], subject, deviceId });
        break;
      }
    }
  }

  if (candidates.length === 0) return { action: 'observe' };
  candidates.sort((a, b) => a.at - b.at
    || a.deviceId.localeCompare(b.deviceId)
    || a.subject.localeCompare(b.subject));
  const target = candidates[0];
  return {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    target: { kind: 'virtual_device', deviceId: target.deviceId },
  };
}
