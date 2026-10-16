import { decide as existingDecide } from './decider.mjs';
import { checkZtnaDeny } from '../xdr/brute-force/respond.mjs';
import { checkWebInjectionDeny } from '../xdr/web-injection/respond.mjs';
import { checkKnownCveDeny } from '../xdr/known-cve/respond.mjs';
import { checkPersistenceDeny } from '../xdr/persistence/respond.mjs';

// trustedSourceAddress는 요청 본문이 아닌 신뢰된 서버/엔진에서 확보한 주소여야 합니다.
// XDR는 명확한 보안 표식에 대한 추가 사전 검사이며, 기존 ZTNA 정책 판정기를 대체하지 않습니다.
export async function decideWithXdr(request, trustedSourceAddress, at = new Date()) {
  const checks = [
    [checkZtnaDeny, 'xdr-brute-force'],
    [checkWebInjectionDeny, 'xdr-web-injection'],
    [checkKnownCveDeny, 'xdr-known-cve'],
    [checkPersistenceDeny, 'xdr-persistence']
  ];
  for (const [check, source] of checks) {
    const rule = await check(trustedSourceAddress, at);
    if (rule) {
      return { effectiveDecision: 'deny', source, evidenceAlertId: rule.evidenceAlertId,
        expiresAt: rule.expiresAt, policyDecision: null };
    }
  }
  const policyDecision = await existingDecide(request);
  return { effectiveDecision: policyDecision.decision, source: 'ztna-policy',
    evidenceAlertId: null, expiresAt: null, policyDecision };
}
