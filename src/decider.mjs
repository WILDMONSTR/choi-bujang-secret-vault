// Use only the fixed judge contract. Ownership is checked by the final resource API.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'signal_provenance',
  'resource_scope',
  'instructor_role_required',
  'unusual_access_context',
  'step_up_required'
]);

const RISK_COUNT_THRESHOLD = 10;
const RISK_WINDOW_SECONDS = 300;
const MAX_AUTH_AGE_SECONDS = 900;
const REQUEST_FIELDS = [
  'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
  'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals'
].sort().join(',');
const SIGNAL_FIELDS = ['source', 'region', 'network', 'hour'].sort().join(',');
const EVENT_FIELDS = ['kind', 'ageSeconds', 'count'].sort().join(',');

// The judge contract represents a resource identifier with :id; the API validates
// the actual identifier and the logged-in owner. Do not assume it must be a UUID here.
const NOTE_ID_PATH = /^\/notes\/[A-Za-z0-9_-]{1,128}$/u;
const ANNOUNCEMENT_ID_PATH = /^\/announcements\/[A-Za-z0-9_-]{1,128}$/u;
const ROUTES = [
  // Collection GET is deliberately absent: do not approve a broad memo list.
  ['notes', 'POST', 'POST /notes', /^\/notes$/u],
  ...['GET', 'PUT', 'DELETE'].map((method) => [
    'notes', method, `${method} /notes/:id`, NOTE_ID_PATH
  ]),
  // Reading announcements is left to the final API's membership check.
  ['announcements', 'GET', 'GET /announcements', /^\/announcements$/u],
  ['announcements', 'POST', 'POST /announcements', /^\/announcements$/u],
  ...['GET', 'PUT', 'DELETE'].map((method) => [
    'announcements', method, `${method} /announcements/:id`, ANNOUNCEMENT_ID_PATH
  ])
];

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const RESTRICTED_RESOURCE_NAMES = /(?:announcements?|class[-_ ]?(?:notices?|announcements?)|teacher[-_ ]?materials?|instructor[-_ ]?materials?|faculty[-_ ]?materials?)/iu;

function response(request, decision, reasonCode, ruleIds) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision,
    reasonCode,
    ruleIds
  };
}

function hasMeaningfulLabel(value) {
  return typeof value === 'string' && value.trim() === value && value.length > 0
    && !['unknown', 'none', 'unavailable', 'null'].includes(value.toLowerCase());
}

function hasValidRecentEvents(request) {
  return Array.isArray(request.recentEvents) && request.recentEvents.length <= 12
    && request.recentEvents.every((event) => event && typeof event === 'object'
      && !Array.isArray(event)
      && Object.keys(event).sort().join(',') === EVENT_FIELDS
      && typeof event.kind === 'string'
      && /^[a-z][a-z0-9_-]{0,63}$/u.test(event.kind)
      && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0
      && Number.isSafeInteger(event.count) && event.count >= 0);
}

// "none"/"unknown" is the contract's explicit unavailable state, not a normal-value
// substitute. We do not infer location, network, or time from missing evidence.
function signalState(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)
      || Object.keys(request).sort().join(',') !== REQUEST_FIELDS) return 'invalid';

  const signals = request.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)
      || Object.keys(signals).sort().join(',') !== SIGNAL_FIELDS
      || !hasValidRecentEvents(request)) return 'invalid';

  if (signals.source === 'none' && signals.region === 'unknown'
      && signals.network === 'unknown'
      && (signals.hour === null || (Number.isInteger(signals.hour) && signals.hour >= 0 && signals.hour <= 23))) {
    return 'unavailable';
  }

  if (signals.source === 'judge_fixture'
      && hasMeaningfulLabel(signals.region)
      && hasMeaningfulLabel(signals.network)
      && Number.isInteger(signals.hour) && signals.hour >= 0 && signals.hour <= 23) {
    return 'fixture';
  }

  return 'invalid';
}

function routeMatches(request) {
  if (!request || !['notes', 'announcements'].includes(request.service)
      || typeof request.method !== 'string' || request.method !== request.method.toUpperCase()
      || typeof request.path !== 'string' || request.path.includes('?') || request.path.includes('#')
      || typeof request.route !== 'string') return false;

  return ROUTES.some(([service, method, route, path]) =>
    service === request.service && method === request.method
      && route === request.route && path.test(request.path));
}

function isRestrictedWrite(request) {
  if (!request || !WRITE_METHODS.has(request.method)) return false;
  const service = typeof request.service === 'string' ? request.service.toLowerCase() : '';
  const pathAndRoute = [request.path, request.route]
    .filter((value) => typeof value === 'string').join(' ');
  return service === 'announcements'
    || ['class_announcements', 'class-announcements', 'teacher_materials',
      'teacher-material', 'instructor_materials', 'instructor-materials',
      'faculty_materials', 'faculty-materials'].includes(service)
    || RESTRICTED_RESOURCE_NAMES.test(pathAndRoute);
}

function hasRecentRiskSignal(request) {
  return request.recentEvents.some((event) =>
    event.kind === 'risk_signal'
      && event.ageSeconds >= 0 && event.ageSeconds <= RISK_WINDOW_SECONDS
      && event.count >= RISK_COUNT_THRESHOLD);
}

function hasUnusualAccessContext(request) {
  const { signals, recentEvents } = request;
  return Number.isInteger(signals.hour)
    && (signals.hour < 6 || signals.hour >= 22)
    && signals.network === 'first_seen'
    && recentEvents.some((event) => event.kind === 'bulk_read'
      && event.ageSeconds <= RISK_WINDOW_SECONDS && event.count >= RISK_COUNT_THRESHOLD);
}

function hasFreshStepUp(request) {
  return request.stepUp?.verified === true
    && Number.isFinite(request.stepUp.authAgeSeconds)
    && request.stepUp.authAgeSeconds >= 0
    && request.stepUp.authAgeSeconds <= MAX_AUTH_AGE_SECONDS;
}

export async function decide(request) {
  if (request?.deviceRegistered !== true) {
    return response(request, 'deny', 'device_not_registered', ['device_registered']);
  }

  if (!hasMeaningfulLabel(request.subjectId) || request.subjectId.length > 256
      || typeof request.deviceId !== 'string' || !/^[0-9a-f]{16}$/u.test(request.deviceId)) {
    return response(request, 'deny', 'step_up_required', ['resource_scope']);
  }

  // Role is absent from the contract, so all writes to announcements and teacher/faculty
  // materials are denied to everyone. PATCH is rejected too.
  if (isRestrictedWrite(request)) {
    return response(request, 'deny', 'step_up_required',
      ['resource_scope', 'instructor_role_required']);
  }

  if (!routeMatches(request)) {
    return response(request, 'deny', 'step_up_required', ['resource_scope']);
  }

  const state = signalState(request);
  if (state === 'invalid') {
    return response(request, 'step_up', 'step_up_required', ['signal_provenance']);
  }

  // Explicit unavailable context is not treated as normal telemetry. The allowed
  // single-note read proceeds to the final API, which must enforce owner + zone.
  if (state === 'unavailable') {
    if (hasRecentRiskSignal(request)) {
      if (hasFreshStepUp(request)) {
        return response(request, 'allow', 'approved',
          ['device_registered', 'resource_scope', 'step_up_required']);
      }
      return response(request, 'step_up', 'step_up_required',
        ['device_registered', 'resource_scope', 'step_up_required']);
    }
    return response(request, 'allow', 'approved', ['device_registered', 'resource_scope']);
  }

  if (hasUnusualAccessContext(request)) {
    if (hasFreshStepUp(request)) {
      return response(request, 'allow', 'approved', [
        'device_registered', 'resource_scope', 'signal_provenance',
        'unusual_access_context', 'step_up_required'
      ]);
    }
    return response(request, 'step_up', 'step_up_required', [
      'device_registered', 'resource_scope', 'signal_provenance',
      'unusual_access_context', 'step_up_required'
    ]);
  }

  if (hasRecentRiskSignal(request)) {
    if (hasFreshStepUp(request)) {
      return response(request, 'allow', 'approved',
        ['device_registered', 'resource_scope', 'step_up_required']);
    }
    return response(request, 'step_up', 'step_up_required',
      ['device_registered', 'resource_scope', 'step_up_required']);
  }

  return response(request, 'allow', 'approved', [
    'device_registered', 'resource_scope', 'signal_provenance'
  ]);
}
