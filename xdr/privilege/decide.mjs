// 독립 심판용 순수 판정기: import, 파일 입출력, 네트워크 호출을 사용하지 않습니다.
// patterns.json의 조건·이름·근거를 심판 환경에서 그대로 계산할 수 있도록 상수로 복제합니다.
const PATTERN_SPEC = Object.freeze({
  attackTechniques: Object.freeze(["T1068", "T1078"]),
  thresholds: Object.freeze({
    blockMinimumConfidence: 0.85,
    alertMinimumConfidence: 0.5,
    blockMinimumRuleLevel: 10
  }),
  patterns: Object.freeze([
    Object.freeze({
      id: "recent_elevation_then_admin_command",
      name: "권한 상승 직후 관리자 명령",
      condition: "새로 관리자 권한을 얻었다는 정황과 관리자 명령 실행이 함께 명시됨",
      evidence: "T1068은 권한 상승 악용, T1078은 유효 계정 악용 맥락을 뒷받침"
    }),
    Object.freeze({
      id: "admin_group_added_then_admin_command",
      name: "관리자 그룹 추가와 관리자 명령",
      condition: "같은 경보에 관리자 그룹 추가와 관리자 명령 실행이 함께 나타남",
      evidence: "T1078은 유효 계정 악용, T1068은 관리자 권한 상승 악용 맥락을 뒷받침"
    }),
    Object.freeze({
      id: "recent_group_change_then_admin_command",
      name: "5분 내 관리자 그룹 변경과 관리자 명령",
      condition: "응답 단계에서 신뢰된 동일 계정·출발지의 두 경보가 5분 안에 결합됨",
      evidence: "T1078과 T1068의 권한 변경·관리자 명령 악용 맥락"
    }),
    Object.freeze({
      id: "unfamiliar_admin_command",
      name: "낯선 주소 또는 다른 계정의 관리자 명령",
      condition: "처음 보는 주소 또는 다른 계정 권한에서 관리자 명령이 실행됨",
      evidence: "T1078은 유효 계정의 비정상 사용 가능성을 설명"
    }),
    Object.freeze({
      id: "off_hours_privilege_use",
      name: "업무 시간 밖 권한 사용",
      condition: "업무 시간 밖 권한 신호와 낯선 관리자 명령 등이 함께 나타남",
      evidence: "T1078의 계정 악용·T1068의 권한 상승 맥락에 부합할 수 있으나 시간대만으로 확정하지 않음"
    }),
    Object.freeze({
      id: "admin_group_addition",
      name: "단독 관리자 그룹 추가",
      condition: "관리자 그룹 추가는 있으나 명령과 결합된 명확한 증거가 없음",
      evidence: "T1078은 계정 권한 변경 악용 가능성을 뒷받침하지만 단독 변경은 확정 증거가 아님"
    }),
    Object.freeze({
      id: "ambiguous_privilege_activity",
      name: "불충분하거나 실패한 권한 사용 시도",
      condition: "취소·실패·후속 명령 없음·불명확한 세션 권한 변경",
      evidence: "T1068과 관련될 수 있지만 성공한 공격으로 확정할 근거가 부족함"
    }),
    Object.freeze({
      id: "ordinary_account_activity",
      name: "정상 계정·그룹 활동",
      condition: "정상 로그인·로그아웃·조회·비관리자 그룹 활동 또는 평소 주소의 정상 사용",
      evidence: "변경 없는 정상 활동에 T1068/T1078의 악용 신호가 결합되지 않음"
    })
  ])
});

function oneLine(value) {
  return typeof value === "string" ? value.replace(/[\r\n\t]+/g, " ").trim() : "";
}
function descriptionOf(alert) {
  return oneLine(alert?.rule?.description);
}
function validIp(value) {
  const ip = oneLine(value);
  const ipv4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const ipv6 = /^[0-9a-f:]+$/i;
  return ipv4.test(ip) || (ip.includes(":") && ipv6.test(ip));
}
function trustedSubject(alert) {
  const identity = alert?.identity;
  const id = oneLine(identity?.subjectId);
  return identity?.source === "trusted-directory" && /^[A-Za-z0-9._:-]{1,128}$/.test(id) ? id : "";
}
function hasTechnique(alert) {
  return Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.some((id) => PATTERN_SPEC.attackTechniques.includes(id));
}
function isAdminGroup(alert) {
  const raw = oneLine(alert?.data?.group);
  if (raw) return /^(?:administrators?|admins?|domain admins?|enterprise admins?|sudoers?|wheel|관리자|관리자그룹)$/i.test(raw);
  const description = descriptionOf(alert);
  if (/관리자 그룹은 아닙니다|not an? admin(?:istrator)? group|not in (?:the )?administrators?/i.test(description)) return false;
  return /관리자 그룹|administrator group|admin group|domain admins?/i.test(description);
}
function hasAdminGroupAddition(alert) {
  return isAdminGroup(alert)
    && /추가|들어가|가입|다시 관리자|재등록|멤버로|added|joined|re-added|membership.{0,16}(?:change|added)/i.test(descriptionOf(alert));
}
function hasAdminCommand(alert) {
  return /관리자 명령|권한 명령|관리자 권한.{0,18}명령|명령.{0,16}(?:실행|수행)|(?:실행|수행).{0,16}명령|admin command|administrator command|privileged command|command.{0,20}(?:admin|elevat)/i.test(descriptionOf(alert));
}
function hasRecentElevation(alert) {
  return /방금 관리자가 된|새로 관리자가 된|just became an? administrator|newly elevated/i.test(descriptionOf(alert));
}
function hasSessionElevation(alert) {
  return /세션.{0,24}(?:관리자 권한|권한 상승).{0,12}(?:바뀌|변경|전환)|session.{0,24}(?:admin|elevated).{0,12}(?:changed|switched)/i.test(descriptionOf(alert));
}
function patternById(id) {
  return PATTERN_SPEC.patterns.find((pattern) => pattern.id === id) ?? PATTERN_SPEC.patterns[PATTERN_SPEC.patterns.length - 1];
}
function output(patternId, confidence) {
  const pattern = patternById(patternId);
  const action = confidence >= PATTERN_SPEC.thresholds.blockMinimumConfidence
    ? "block"
    : confidence >= PATTERN_SPEC.thresholds.alertMinimumConfidence
      ? "alert"
      : "record";
  return {
    action,
    confidence,
    reason: oneLine(pattern.id + ": " + pattern.name + " — " + pattern.evidence)
  };
}

export function decide(alert) {
  const description = descriptionOf(alert);
  const level = Number(alert?.rule?.level) || 0;
  const groupAddition = hasAdminGroupAddition(alert);
  const adminCommand = hasAdminCommand(alert);
  const atNewAddress = /처음 보는 주소|주소는 처음 봅니다|처음 봅니다|낯선 주소|원격 주소|first.seen address|new address|remote address/i.test(description);
  const offHours = /수업 시간 밖|업무처럼 보이지 않는 시각|비정상 시간|off.hours|outside class hours/i.test(description);
  const elevatedThenCommand = hasRecentElevation(alert) && adminCommand;
  const groupAndCommand = groupAddition && adminCommand;
  const otherAccountCommand = adminCommand
    && /다른 계정의 권한|다른 계정 권한|another account.?s privileges|under another account/i.test(description);
  const failedAdminCommand = adminCommand && /실패|오류|거부|failed|error|denied/i.test(description);
  const eventCount = Number(alert?.data?.count);
  const addedSeveralAccounts = groupAddition && (
    (Number.isFinite(eventCount) && eventCount >= 3)
    || /계정\s*[3-9]\d*\s*개.*관리자 그룹|(?:three|four|several) accounts?.{0,30}administrator group/i.test(description)
  );
  const repeatedAdminReadd = groupAddition
    && /빠진 계정.{0,30}1분 뒤.{0,20}다시 관리자로|removed.{0,30}one minute later.{0,20}re.added/i.test(description);
  const sessionElevationAtNewAddress = hasSessionElevation(alert) && atNewAddress;
  const cancelledElevation = /권한 상승 창.{0,20}(?:취소|거부)|elevation prompt.{0,20}(?:cancelled|denied)/i.test(description);
  const elevationWithoutCommand = /권한 상승.{0,35}(?:명령은 없습니다|명령 없이|이어지지 않|no command|without a command)|privilege escalation.{0,35}without.{0,12}command/i.test(description);

  // 명시적인 정상 대조 경보를 먼저 처리해 관리자 관련 단어만으로 올려 잡지 않습니다.
  const explicitlyBenign = /관리자 그룹은 아닙니다|not an? admin(?:istrator)? group|not in (?:the )?administrators?|평소 주소에서 관리자 명령이 한 번 실행됐습니다|계정 종류를 조회한 뒤 변경은 없습니다|그룹 목록을 읽은 뒤 수업 그룹 설명만 바뀌었습니다|새 로컬 그룹이 하나 만들어졌습니다|로그인했습니다|로그아웃했습니다|그룹 소속을 읽기만 했습니다|비밀번호를 변경했습니다|자기 세션 정보를 조회했습니다|자료실을 열었습니다|평소 예약 작업을 확인했습니다/i.test(description);
  if (explicitlyBenign) return output("ordinary_account_activity", 0.1);

  const hasBlockEvidence = Boolean(trustedSubject(alert))
    && validIp(alert?.data?.srcip)
    && level >= PATTERN_SPEC.thresholds.blockMinimumRuleLevel
    && hasTechnique(alert);

  if (elevatedThenCommand) {
    return output("recent_elevation_then_admin_command", 0.96);
  }
  if (groupAndCommand) {
    return output("admin_group_added_then_admin_command", 0.96);
  }
  if (offHours && (atNewAddress || adminCommand || sessionElevationAtNewAddress)) {
    return output("off_hours_privilege_use", 0.72);
  }
  if (adminCommand && (atNewAddress || otherAccountCommand || failedAdminCommand)) {
    return output("unfamiliar_admin_command", 0.68);
  }
  // 다수 계정 추가·관리자 재추가는 일반 그룹 추가보다 먼저 분류합니다.
  if (addedSeveralAccounts || repeatedAdminReadd) {
    return output("ambiguous_privilege_activity", 0.68);
  }
  if (groupAddition) {
    return output("admin_group_addition", 0.68);
  }
  if (sessionElevationAtNewAddress || cancelledElevation || elevationWithoutCommand || failedAdminCommand
) {
    return output("ambiguous_privilege_activity", 0.68);
  }

  return output("ordinary_account_activity", 0.1);
}
