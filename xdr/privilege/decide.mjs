// 독립 심판용 순수 판정기: import, 파일 입출력, 네트워크 호출을 사용하지 않습니다.
const BLOCK_MIN_LEVEL = 10;
const ADMIN_TECHNIQUES = new Set(["T1078", "T1068", "T1098"]);

function oneLine(value) {
  return typeof value === "string" ? value.replace(/[\r\n\t]+/g, " ").trim() : "";
}
function descriptionOf(alert) {
  return oneLine(alert?.rule?.description);
}
function isValidIp(value) {
  const ip = oneLine(value);
  const ipv4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const ipv6 = /^[0-9a-f:]+$/i;
  return ipv4.test(ip) || (ip.includes(":") && ipv6.test(ip));
}
function identitySubject(alert) {
  const identity = alert?.identity;
  const id = oneLine(identity?.subjectId);
  // Only an identity resolver's normalized account ID is eligible for session denial.
  if (identity?.source !== "trusted-directory" || !/^[A-Za-z0-9._:-]{1,128}$/.test(id)) return "";
  return id;
}
function userOf(alert) {
  const user = oneLine(alert?.data?.srcuser);
  return /^[A-Za-z0-9._@-]{1,128}$/.test(user) ? user : "";
}
function hasTechnique(alert) {
  return Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.some((id) => ADMIN_TECHNIQUES.has(id));
}
function isAdminGroup(alert) {
  const raw = oneLine(alert?.data?.group);
  if (raw) return /^(?:administrators?|admins?|domain admins?|enterprise admins?|sudoers?|wheel|관리자|관리자그룹)$/i.test(raw);
  const description = descriptionOf(alert);
  if (/관리자 그룹은 아닙니다|not an? admin(?:istrator)? group|not in (?:the )?administrators?/i.test(description)) return false;
  return /관리자 그룹|administrator group|admin group|domain admins?/i.test(description);
}
function hasAdminGroupAddition(alert) {
  if (!isAdminGroup(alert)) return false;
  return /추가|들어가|가입|다시 관리자|재등록|멤버로|added|joined|membership.{0,16}(?:change|added)/i.test(descriptionOf(alert));
}
function hasAdminCommand(alert) {
  const description = descriptionOf(alert);
  return /관리자 명령|권한 명령|관리자 권한.{0,18}명령|명령.{0,16}(?:실행|수행)|(?:실행|수행).{0,16}명령|admin command|administrator command|privileged command|command.{0,20}(?:admin|elevat)/i.test(description);
}
function hasDirectElevationThenCommand(alert) {
  const description = descriptionOf(alert);
  return /방금 관리자가 된|새로 관리자가 된|just became an? administrator|newly elevated/i.test(description)
    && hasAdminCommand(alert);
}
function hasSessionElevation(alert) {
  return /세션.{0,24}(?:관리자 권한|권한 상승).{0,12}(?:바뀌|변경|전환)|session.{0,24}(?:admin|elevated).{0,12}(?:changed|switched)/i.test(descriptionOf(alert));
}
function output(action, confidence, reason) {
  return { action, confidence, reason };
}

export function decide(alert) {
  const description = descriptionOf(alert);
  const level = Number(alert?.rule?.level) || 0;
  const user = userOf(alert);
  const subjectId = identitySubject(alert);
  const validSource = isValidIp(alert?.data?.srcip);
  const technique = hasTechnique(alert);
  const groupAddition = hasAdminGroupAddition(alert);
  const adminCommand = hasAdminCommand(alert);
  const directPair = groupAddition && adminCommand;
  const directSequence = hasDirectElevationThenCommand(alert);
  const needsNormalizedIdentity = Boolean(subjectId);

  // Session denial is account-scoped: no block without an authoritative subject ID.
  if (needsNormalizedIdentity && validSource && user && technique && level >= BLOCK_MIN_LEVEL
      && (directPair || directSequence)) {
    return output("block", 0.96, directSequence
      ? "명확한 권한 상승 후 관리자 명령: recent_elevation_then_admin_command"
      : "명확한 관리자 그룹 변경과 관리자 명령 결합: admin_group_added_then_admin_command");
  }

  const suspiciousGroupChange = groupAddition
    || (isAdminGroup(alert) && /제거|다시|재등록|removed|re-added|added/i.test(description));
  const suspiciousCommand = adminCommand && (
    level >= 8
    || /처음 보는|낯선|원격 주소|업무처럼 보이지 않는|수업 시간 밖|다른 계정|실패|취소|비정상|first.seen|off.hours|another account|failed|cancelled/i.test(description)
  );
  const suspiciousSession = hasSessionElevation(alert)
    || /권한 상승 창|elevation prompt|권한으로 바뀌|권한 상승이/i.test(description);
  const explicitlyNonAdminGroup = Boolean(oneLine(alert?.data?.group)) && !isAdminGroup(alert)
    && /관리자 그룹은 아닙니다|not an? admin(?:istrator)? group|not in (?:the )?administrators?/i.test(description);
  const suspiciousPattern = !explicitlyNonAdminGroup
    && /관리자.{0,18}(?:그룹|권한)|권한.{0,18}(?:상승|변경)|administrator group|privilege escalation/i.test(description);
  const hasClearRiskSignal = suspiciousGroupChange || suspiciousCommand || suspiciousSession || suspiciousPattern;

  if (hasClearRiskSignal) {
    return output("alert", 0.68,
      "검토 필요: 권한 변경 또는 관리자 사용 신호는 있으나 계정·행위의 결합 근거가 충분하지 않아 차단하지 않음");
  }

  return output("record", 0.1, "알려진 비정상 권한 상승 신호 없음");
}
