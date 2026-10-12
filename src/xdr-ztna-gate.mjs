import { decide as existingDecide } from './decider.mjs';
import { checkZtnaDeny } from '../xdr/brute-force/respond.mjs';

// trustedSourceAddress는 요청 본문이 아닌 신뢰된 서버/엔진에서 확보한 주소여야 합니다.
export async function decideWithXdr(request, trustedSourceAddress, at = new Date()) {
  const rule = await checkZtnaDeny(trustedSourceAddress, at);
  if (rule) {
    return {
      effectiveDecision: 'deny',
      source: 'xdr-brute-force',
      evidenceAlertId: rule.evidenceAlertId,
      expiresAt: rule.expiresAt,
      policyDecision: null
    };
  }

  const policyDecision = await existingDecide(request);
  return {
    effectiveDecision: policyDecision.decision,
    source: 'ztna-policy',
    evidenceAlertId: null,
    expiresAt: null,
    policyDecision
  };
}
