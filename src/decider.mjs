// 계약에 정의된 요청 값만 사용합니다. 브라우저가 보낸 신원이나 역할을 추측하지 않습니다.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'signal_provenance',
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

function hasMeaningfulLabel(value) {
  return typeof value === 'string' && value.trim() === value && value.length > 0
    && !['unknown', 'none', 'unavailable', 'null'].includes(value.toLowerCase());
}

// The only documented signal source available for local fixtures is judge_fixture.
// "none", missing context, and client-header labels are not trusted evidence.
function hasValidSignalContext(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)
      || Object.keys(request).sort().join(',') !== REQUEST_FIELDS) return false;

  const signals = request.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)
      || Object.keys(signals).sort().join(',') !== SIGNAL_FIELDS
      || signals.source !== 'judge_fixture'
      || !hasMeaningfulLabel(signals.region)
      || !hasMeaningfulLabel(signals.network)
      || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23) {
    return false;
  }

  if (!Array.isArray(request.recentEvents) || request.recentEvents.length > 12) return false;
  return request.recentEvents.every((event) => event && typeof event === 'object'
    && !Array.isArray(event)
    && Object.keys(event).sort().join(',') === EVENT_FIELDS
    && typeof event.kind === 'string' && /^[a-z][a-z0-9_-]{0,63}$/u.test(event.kind)
    && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0
    && Number.isSafeInteger(event.count) && event.count >= 0);
}

function response(request, decision, reasonCode, ruleIds) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode,
    ruleIds
  };
}

function hasRecentRiskSignal(request) {
  if (!Array.isArray(request.recentEvents)) return false;
  return request.recentEvents.some((event) => {
    const age = Number(event?.ageSeconds);
    const count = Number(event?.count);
    return event?.kind === 'risk_signal' &&
      Number.isFinite(age) && age >= 0 && age <= RISK_WINDOW_SECONDS &&
      Number.isFinite(count) && count >= RISK_COUNT_THRESHOLD;
  });
}


function hasUnusualAccessContext(request) {
  const { signals, recentEvents } = request;
  const unusualHour = signals.hour < 6 || signals.hour >= 22;
  const firstSeenNetwork = signals.network === 'first_seen';
  const suddenBulkRead = recentEvents.some((event) => event.kind === 'bulk_read'
    && event.ageSeconds <= RISK_WINDOW_SECONDS
    && event.count >= RISK_COUNT_THRESHOLD);

  // Region alone is deliberately not a trigger; this rule requires all three signals.
  return unusualHour && firstSeenNetwork && suddenBulkRead;
}

function hasFreshStepUp(request) {
  const stepUp = request.stepUp;
  return stepUp?.verified === true &&
    Number.isFinite(stepUp.authAgeSeconds) &&
    stepUp.authAgeSeconds >= 0 &&
    stepUp.authAgeSeconds <= MAX_AUTH_AGE_SECONDS;
}

export async function decide(request) {
  if (request.deviceRegistered !== true) {
    return response(request, 'deny', 'device_not_registered', ['device_registered']);
  }
  if (!hasValidSignalContext(request)) {
    return response(request, 'step_up', 'step_up_required', ['signal_provenance']);
  }
  if (hasUnusualAccessContext(request)) {
    if (hasFreshStepUp(request)) {
      return response(request, 'allow', 'approved', [
        'device_registered', 'signal_provenance', 'unusual_access_context', 'step_up_required'
      ]);
    }
    return response(request, 'step_up', 'step_up_required', [
      'device_registered', 'signal_provenance', 'unusual_access_context', 'step_up_required'
    ]);
  }
  if (hasRecentRiskSignal(request)) {
    if (hasFreshStepUp(request)) {
      return response(request, 'allow', 'approved', ['device_registered', 'step_up_required']);
    }
    return response(request, 'step_up', 'step_up_required', ['device_registered', 'step_up_required']);
  }
  return response(request, 'allow', 'approved', ['device_registered']);
}
