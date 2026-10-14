// 9단계: 같은 가명 주체의 GET 사건이 10분 안에 120건을 초과하면 회수를 제안합니다.
// 계약에는 at, method, identity.sub만 사용합니다. 실제 권한 회수는 수행하지 않습니다.
const READ_LIMIT = 120;
const WINDOW_MS = 10 * 60 * 1000;

function invalidEvent() {
  throw new TypeError('invalid_detection_event');
}

function parseEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    invalidEvent();
  }

  const rawAt = event.at;
  if (typeof rawAt !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(rawAt)) {
    invalidEvent();
  }
  const at = Date.parse(rawAt);
  if (!Number.isFinite(at) || new Date(at).toISOString() !== rawAt) {
    invalidEvent();
  }

  if (typeof event.method !== 'string' || event.method.length === 0
      || event.method.length > 16) {
    invalidEvent();
  }

  const identity = event.identity;
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)
      || typeof identity.sub !== 'string'
      || identity.sub.trim() !== identity.sub
      || identity.sub.length === 0 || identity.sub.length > 256) {
    invalidEvent();
  }

  // Project only the three fields in the detector contract. Other metadata,
  // including absent device/network properties, is never read or returned.
  return { at, method: event.method, subject: identity.sub };
}

export function detect(input) {
  const events = Array.isArray(input)
    ? input
    : input && typeof input === 'object'
      ? [input]
      : invalidEvent();

  const readsBySubject = new Map();
  for (const rawEvent of events) {
    const event = parseEvent(rawEvent);
    if (event.method !== 'GET') continue;
    if (!readsBySubject.has(event.subject)) readsBySubject.set(event.subject, []);
    readsBySubject.get(event.subject).push(event.at);
  }

  const candidates = [];
  for (const [subject, timestamps] of readsBySubject) {
    timestamps.sort((a, b) => a - b);
    let left = 0;
    for (let right = 0; right < timestamps.length; right += 1) {
      while (timestamps[right] - timestamps[left] > WINDOW_MS) left += 1;
      if (right - left + 1 > READ_LIMIT) {
        candidates.push({ at: timestamps[right], subject });
        break;
      }
    }
  }

  if (candidates.length === 0) return { action: 'observe' };

  // If multiple subjects cross the limit, choose the first crossing time.
  // A lexical tie-break makes the result deterministic for simultaneous crossings.
  candidates.sort((a, b) => a.at - b.at || a.subject.localeCompare(b.subject));
  return {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject: candidates[0].subject,
  };
}
