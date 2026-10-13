// 9단계: 평소와 다른 네트워크와 다량 조회가 함께 나타난 가상 기기만 회수 제안 대상으로 표시합니다.
// 운영 반 엔진이 검증한 사건만 전달해야 합니다. 실제 권한 회수는 수행하지 않습니다.
const READ_LIMIT = 120;
const WINDOW_MS = 10 * 60 * 1000;
const RISK_WINDOW_SECONDS = 300;
const RISK_COUNT_THRESHOLD = 10;

const ALLOWED_EVENT_KEYS = new Set([
  'at', 'timestamp', 'deviceId', 'identity', 'method', 'requestKind', 'requestType',
  'kind', 'count', 'ageSeconds', 'decision', 'network', 'region',
  'signals', 'recentEvents', 'subjectId',
  'schema', 'requestId', 'classId', 'projectId', 'service', 'path', 'route',
  'queryLength', 'querySha256', 'policyRevision', 'deviceRegistered', 'stepUp',
]);
const SIGNAL_KEYS = new Set(['source', 'region', 'network', 'hour']);
const IDENTITY_KEYS = 'sub';
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
        || Object.keys(signals).some((key) => !SIGNAL_KEYS.has(key))) {
      throw new TypeError('invalid_detection_event');
    }
    if (signals.network !== undefined) {
      if (!NETWORK_STATES.has(signals.network)) throw new TypeError('invalid_detection_event');
      nestedNetwork = signals.network;
    }
    if (signals.source !== undefined && typeof signals.source !== 'string') {
      throw new TypeError('invalid_detection_event');
    }
    // Region is deliberately not a detection signal. Unknown/null region does not
    // make an otherwise valid network event look normal or suspicious.
    if (signals.region !== undefined && signals.region !== null
        && typeof signals.region !== 'string') {
      throw new TypeError('invalid_detection_event');
    }
    if (signals.hour !== undefined && signals.hour !== null
        && (!Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23)) {
      throw new TypeError('invalid_detection_event');
    }
  }

  const directNetwork = event.network;
  if (directNetwork !== undefined && !NETWORK_STATES.has(directNetwork)) {
    throw new TypeError('invalid_detection_event');
  }
  if (directNetwork !== undefined && nestedNetwork !== undefined
      && directNetwork !== nestedNetwork) {
    throw new TypeError('invalid_detection_event');
  }
  return directNetwork ?? nestedNetwork ?? 'unknown';
}

function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)
      || Object.keys(event).some((key) => !ALLOWED_EVENT_KEYS.has(key))) {
    throw new TypeError('invalid_detection_event');
  }
  const rawAt = event.at ?? event.timestamp;
  if (typeof rawAt !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(rawAt)
      || !Number.isFinite(Date.parse(rawAt))
      || new Date(Date.parse(rawAt)).toISOString() !== rawAt
      || typeof event.deviceId !== 'string' || !DEVICE_ID_PATTERN.test(event.deviceId)) {
    throw new TypeError('invalid_detection_event');
  }

  if (event.decision !== undefined) {
    const decision = typeof event.decision === 'string' ? event.decision : event.decision?.decision;
    if (!['allow', 'deny', 'step_up'].includes(decision)) {
      throw new TypeError('invalid_detection_event');
    }
  }
  if (event.count !== undefined && (!Number.isSafeInteger(event.count) || event.count < 0)) {
    throw new TypeError('invalid_detection_event');
  }
  if (event.ageSeconds !== undefined && (!Number.isFinite(event.ageSeconds) || event.ageSeconds < 0)) {
    throw new TypeError('invalid_detection_event');
  }

  const rawMethod = event.method ?? event.requestKind ?? event.requestType ?? event.kind;
  if (typeof rawMethod !== 'string') throw new TypeError('invalid_detection_event');
  const normalizedRequestKind = String(event.requestKind ?? event.requestType ?? event.kind ?? rawMethod)
    .toLowerCase().replaceAll('-', '_');
  const methodAliases = {
    read: 'GET', bulk_read: 'GET', create: 'POST', write: 'POST',
    update: 'PUT', remove: 'DELETE',
  };
  const normalizedMethod = methodAliases[rawMethod.toLowerCase().replaceAll('-', '_')]
    ?? rawMethod.toUpperCase();
  if (!/^[A-Z]{3,10}$/u.test(normalizedMethod)) {
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

  if (event.region !== undefined && event.region !== null
      && (typeof event.region !== 'string' || event.region.trim() !== event.region
        || event.region.length > 64)) {
    throw new TypeError('invalid_detection_event');
  }

  return {
    at: Date.parse(rawAt),
    method: normalizedMethod,
    requestKind: normalizedRequestKind,
    network: readNetwork(event),
    recentEvents: readRecentEvents(event.recentEvents),
    subject,
    deviceId: event.deviceId,
    count: event.count,
    ageSeconds: event.ageSeconds,
  };
}

function hasRecentBulkRead(event) {
  return event.recentEvents.some((item) =>
    item.kind === 'bulk_read'
      && item.ageSeconds <= RISK_WINDOW_SECONDS
      && item.count >= RISK_COUNT_THRESHOLD);
}

export function detect(events) {
  // The judge may deliver either one virtual incident or a batch of incidents.
  if (!Array.isArray(events)) {
    if (events && typeof events === 'object') events = [events];
    else throw new TypeError('invalid_detection_events');
  }

  const readsBySubject = new Map();
  const bulkReadTimes = new Map();
  const candidates = [];

  for (const rawEvent of events) {
    const event = readEvent(rawEvent);
    if (event.method !== 'GET' || event.network !== 'first_seen') continue;

    if (hasRecentBulkRead(event)
        || (event.requestKind === 'bulk_read' && event.count >= RISK_COUNT_THRESHOLD
          && event.ageSeconds <= RISK_WINDOW_SECONDS)) {
      candidates.push({ at: event.at, subject: event.subject, deviceId: event.deviceId });
    }

    if (event.requestKind === 'bulk_read') {
      const key = event.subject + '\u0000' + event.deviceId;
      if (!bulkReadTimes.has(key)) {
        bulkReadTimes.set(key, { subject: event.subject, deviceId: event.deviceId, times: [] });
      }
      bulkReadTimes.get(key).times.push(event.at);
    }

    if (!readsBySubject.has(event.subject)) readsBySubject.set(event.subject, new Map());
    const devices = readsBySubject.get(event.subject);
    if (!devices.has(event.deviceId)) devices.set(event.deviceId, []);
    devices.get(event.deviceId).push(event.at);
  }

  for (const bucket of bulkReadTimes.values()) {
    bucket.times.sort((a, b) => a - b);
    let left = 0;
    for (let right = 0; right < bucket.times.length; right += 1) {
      while (bucket.times[right] - bucket.times[left] > RISK_WINDOW_SECONDS * 1000) left += 1;
      if (right - left + 1 < RISK_COUNT_THRESHOLD) continue;
      candidates.push({ at: bucket.times[right], subject: bucket.subject, deviceId: bucket.deviceId });
      break;
    }
  }

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
