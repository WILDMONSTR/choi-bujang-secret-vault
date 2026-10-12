// 계약에 정의된 요청 값만 사용합니다. 브라우저가 보낸 신원이나 역할을 추측하지 않습니다.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required'
]);

const RISK_COUNT_THRESHOLD = 10;
const RISK_WINDOW_SECONDS = 300;
const MAX_AUTH_AGE_SECONDS = 900;

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
  if (hasRecentRiskSignal(request)) {
    if (hasFreshStepUp(request)) {
      return response(request, 'allow', 'approved', ['device_registered', 'step_up_required']);
    }
    return response(request, 'step_up', 'step_up_required', ['device_registered', 'step_up_required']);
  }
  return response(request, 'allow', 'approved', ['device_registered']);
}
