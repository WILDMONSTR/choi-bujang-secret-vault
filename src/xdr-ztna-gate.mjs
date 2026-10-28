import { decide as existingDecide } from "./decider.mjs";
import { checkZtnaDeny } from "../xdr/brute-force/respond.mjs";
import { checkWebInjectionDeny } from "../xdr/web-injection/respond.mjs";
import { checkKnownCveDeny } from "../xdr/known-cve/respond.mjs";
import { checkPersistenceDeny } from "../xdr/persistence/respond.mjs";
import { checkExfiltrationDeny } from "../xdr/exfiltration/respond.mjs";
import { checkPrivilegeSessionDeny } from "../xdr/privilege/respond.mjs";

// trustedSourceAddress와 request.subjectId는 요청 본문이 아니라 인증·ZTNA 엔진이 검증한 값이어야 합니다.
// XDR는 추가 사전 검사이며 기존 src/decider.mjs 정책을 대체하지 않습니다.
export async function decideWithXdr(request, trustedSourceAddress, at = new Date()) {
  // 권한 상승 사건은 IP가 아니라 인증된 계정 ID의 세션을 기준으로 확인합니다.
  const subjectId = typeof request?.subjectId === "string" ? request.subjectId.trim() : "";
  const privilegeRule = await checkPrivilegeSessionDeny(subjectId, at);
  if (privilegeRule) {
    return {
      effectiveDecision: "deny",
      source: "xdr-privilege",
      evidenceAlertId: Array.isArray(privilegeRule.evidenceAlertIds) ? privilegeRule.evidenceAlertIds[0] ?? null : null,
      expiresAt: privilegeRule.expiresAt,
      policyDecision: null
    };
  }

  const checks = [
    [checkZtnaDeny, "xdr-brute-force"],
    [checkWebInjectionDeny, "xdr-web-injection"],
    [checkKnownCveDeny, "xdr-known-cve"],
    [checkPersistenceDeny, "xdr-persistence"],
    [checkExfiltrationDeny, "xdr-exfiltration"]
  ];
  for (const [check, source] of checks) {
    const rule = await check(trustedSourceAddress, at);
    if (rule) {
      return {
        effectiveDecision: "deny",
        source,
        evidenceAlertId: rule.evidenceAlertId,
        expiresAt: rule.expiresAt,
        policyDecision: null
      };
    }
  }
  const policyDecision = await existingDecide(request);
  return {
    effectiveDecision: policyDecision.decision,
    source: "ztna-policy",
    evidenceAlertId: null,
    expiresAt: null,
    policyDecision
  };
}
