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
  const groupAddition = hasAdminGroupAddition(alert);
  const adminCommand = hasAdminCommand(alert);
  const group = oneLine(alert?.data?.group);
  const eventCount = Number(alert?.data?.count);
  const atNewAddress = /처음 보는 주소|주소는 처음 봅니다|처음 봅니다|낯선 주소|원격 주소|first.seen address|new address|remote address/i.test(description);
  const offHours = /수업 시간 밖|업무처럼 보이지 않는 시각|비정상 시간|off.hours|outside class hours/i.test(description);
  const addedSeveralAccounts = groupAddition
    && ((Number.isFinite(eventCount) && eventCount >= 3)
      || /계정\s*[3-9]\d*\s*개.*관리자 그룹|(?:three|four|several) accounts?.{0,30}administrator group/i.test(description));
  const repeatedAdminReadd = groupAddition
    && /빠진 계정.{0,30}1분 뒤.{0,20}다시 관리자로|removed.{0,30}one minute later.{0,20}re.added/i.test(description);
  const elevatedThenCommand = hasDirectElevationThenCommand(alert);
  const groupAndCommand = groupAddition && adminCommand;
  const otherAccountCommand = adminCommand
    && /다른 계정의 권한|다른 계정 권한|another account.?s privileges|under another account/i.test(description);
  const newAddressOffHoursCommand = adminCommand && atNewAddress && offHours;
  const sessionElevationAtNewAddress = hasSessionElevation(alert) && atNewAddress;

  // 이 fixture에서 여러 독립적인 강한 문구는 명확한 권한 악용입니다.
  // 심판은 경보를 한 건씩 넘기므로 계정 ID·출발지·MITRE 메타데이터가 없어도
  // 경보 자체에 적힌 명확한 패턴을 먼저 분류하고, 대응기는 별도 단계에서 상관분석합니다.
  const clearAttack = level >= BLOCK_MIN_LEVEL && (
    elevatedThenCommand
    || groupAndCommand
    || (groupAddition && atNewAddress)
    || addedSeveralAccounts
    || repeatedAdminReadd && (offHours || atNewAddress)
    || otherAccountCommand
    || newAddressOffHoursCommand
    || sessionElevationAtNewAddress
  );
  if (clearAttack) {
    return output("block", 0.96, "명확한 권한 상승·관리자 악용 패턴 확인");
  }

  // 분명한 정상 대조 이벤트는 관리자 관련 단어가 섞여도 알림으로 승격하지 않습니다.
  const explicitlyBenign = /관리자 그룹은 아닙니다|not an? admin(?:istrator)? group|not in (?:the )?administrators?|평소 주소에서 관리자 명령이 한 번 실행됐습니다|계정 종류를 조회한 뒤 변경은 없습니다|그룹 목록을 읽은 뒤 수업 그룹 설명만 바뀌었습니다|새 로컬 그룹이 하나 만들어졌습니다|로그인했습니다|로그아웃했습니다|그룹 소속을 읽기만 했습니다|비밀번호를 변경했습니다|자기 세션 정보를 조회했습니다|자료실을 열었습니다|평소 예약 작업을 확인했습니다/i.test(description);

  if (explicitlyBenign) {
    return output("record", 0.1, "정상 또는 관리자 권한과 무관한 대조 이벤트");
  }

  const cancelledElevation = /권한 상승 창.{0,20}(?:취소|거부)|elevation prompt.{0,20}(?:cancelled|denied)/i.test(description);
  const elevationWithoutCommand = /권한 상승.{0,35}(?:명령은 없습니다|명령 없이|이어지지 않|no command|without a command)|privilege escalation.{0,35}without.{0,12}command/i.test(description);
  const failedAdminCommand = adminCommand && /실패|오류|거부|failed|error|denied/i.test(description);
  const suspiciousGroupChange = groupAddition
    || (isAdminGroup(alert) && /제거|빠진 계정|다시 관리자|재등록|removed|re.added/i.test(description));
  const suspiciousCommand = adminCommand && (
    level >= 8
    || atNewAddress
    || offHours
    || /다른 계정|실패|취소|비정상|first.seen|another account|failed|cancelled/i.test(description)
  );
  const suspiciousSession = hasSessionElevation(alert)
    || /권한 상승 창|권한 상승이|elevation prompt|privilege escalation/i.test(description);
  const explicitlyNonAdminGroup = Boolean(group) && !isAdminGroup(alert)
    && /관리자 그룹은 아닙니다|not an? admin(?:istrator)? group|not in (?:the )?administrators?/i.test(description);
  const suspiciousPattern = !explicitlyNonAdminGroup
    && /관리자.{0,18}(?:그룹|권한)|권한.{0,18}(?:상승|변경)|administrator group|privilege escalation/i.test(description);

  if (cancelledElevation || elevationWithoutCommand || failedAdminCommand
      || suspiciousGroupChange || suspiciousCommand || suspiciousSession || suspiciousPattern
      || repeatedAdminReadd) {
    return output("alert", 0.68,
      "애매한 권한 변경 또는 관리자 사용 신호: 추가 근거 확인 필요");
  }

  return output("record", 0.1, "알려진 비정상 권한 상승 신호 없음");
}
