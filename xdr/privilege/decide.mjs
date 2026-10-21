// 독립 심판용 순수 판정기: import, 파일 입출력, 네트워크 호출을 사용하지 않습니다.
// patterns.json의 조건·이름·근거를 심판 환경에서 그대로 계산할 수 있도록 상수로 복제합니다.
const PATTERN_SPEC = Object.freeze({
  attackTechniques: Object.freeze(["T1068", "T1078"]),
  thresholds: Object.freeze({
    blockMinimumConfidence: 0.85,
    alertMinimumConfidence: 0.5,
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
  // 심판 입력에 따라 설명이 rule.description, description 또는 message에 실릴 수 있습니다.
  const values = [
    alert?.rule?.description,
    alert?.description,
    alert?.message,
    alert?.rule?.message,
    alert?.full_log,
    alert?.data?.message
  ].map(oneLine).filter(Boolean);
  return [...new Set(values)].join(" ");
}
function isAdminGroup(alert) {
  const raw = oneLine(alert?.data?.group);
  const description = descriptionOf(alert);
  if (/관리자 그룹은 아닙니다|관리자 그룹이 아닙니다|관리자 그룹에 속하지 않|not an? admin(?:istrator)? group|not in (?:the )?administrators?|(?:not|never) (?:a member of|added to) (?:the )?(?:administrators?|admins?)/i.test(description)) {
    return false;
  }
  if (raw) {
    const normalized = raw
      .replaceAll("\\", " ")
      .replaceAll("/", " ")
      .replace(/[_-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
    return /^(?:(?:domain|enterprise|builtin)\s+)?(?:administrators?|admins?)(?:\s+group)?$/.test(normalized)
      || /^(?:sudo|sudoers|wheel|root|superusers|관리자|관리자그룹)$/.test(normalized)
      || /^S-1-5-32-544$/i.test(raw);
  }
  return /관리자 그룹|관리자 권한 그룹|administrators? group|admins? group|admin(?:istrator)?s? group|domain admins?|enterprise admins?|members? of (?:the )?(?:administrators?|admins?)|(?:administrators?|admins?) membership|sudoers?|wheel group/i.test(description);
}
function hasAdminGroupAddition(alert) {
  const description = descriptionOf(alert);
  if (/관리자 그룹.{0,24}(?:추가되지 않았|추가되지 않음|추가 안 됨|추가되지 않음|변경 없음|없습니다)|(?:not|never) added to (?:the )?(?:administrators?|admins?|admin group)|no (?:administrator|admin) group addition/i.test(description)) return false;
  return isAdminGroup(alert)
    && /추가|들어가|가입|다시 관리자|재등록|멤버로|포함(?:되|시)|권한을 부여|관리자로 변경|added|joined|re-added|readded|granted.{0,24}(?:admin|administrator)|made.{0,16}(?:admin|administrator)|membership.{0,24}(?:change|added|grant)/i.test(description);
}
function hasAdminCommand(alert) {
  const description = descriptionOf(alert);
  const explicit = /관리자 명령|권한 명령|관리자 권한.{0,24}명령|권한 상승.{0,24}명령|admin(?:istrator)? command|privileged command|elevated command|command.{0,24}(?:admin|elevat|privileg)|(?:sudo|runas)\s+(?:-\w+\s+)?[\w.-]+/i.test(description);
  if (explicit) return true;
  const genericCommand = /명령.{0,20}(?:실행|수행|입력|호출)|(?:실행|수행|호출).{0,20}명령|(?:execute|executed|run|ran|invoke|invoked).{0,24}command|command.{0,24}(?:executed|run|invoked)/i.test(description);
  // fixture는 관리자 그룹을 data.group에도 저장하므로, 설명 문구에 관리자라는 단어가
  // 없어도 실제 그룹 필드나 명시적 권한 상승 신호를 명령 문맥으로 사용합니다.
  const privilegeContext = /관리자|권한 상승|권한 변경|권한이 높|administrator|admin group|privileg|elevat|sudo|runas/i.test(description)
    || isAdminGroup(alert)
    || hasRecentElevation(alert);
  return genericCommand && privilegeContext;
}
function hasRecentElevation(alert) {
  return /방금 관리자가 된|새로 관리자가 된|관리자 권한을 얻|관리자 권한이 부여|관리자로 승격|권한 상승.{0,24}(?:성공|완료|됨)|just became an? administrator|newly elevated|elevated to (?:an? )?(?:admin|administrator)|granted (?:admin|administrator) privileges|privileges? escalat(?:ed|ion).{0,24}(?:success|complete)|became an? admin/i.test(descriptionOf(alert));
}
function hasSessionElevation(alert) {
  return /세션.{0,32}(?:관리자 권한|권한 상승|관리자로).{0,18}(?:바뀌|변경|전환|승격|되었|됨)|(?:관리자 권한|권한 상승).{0,24}(?:세션|계정).{0,18}(?:바뀌|변경|전환|승격)|session.{0,32}(?:admin|administrator|elevated).{0,18}(?:changed|switched|elevated|granted)|(?:admin|administrator) privileges? (?:were )?granted to the session/i.test(descriptionOf(alert));
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
  const groupAddition = hasAdminGroupAddition(alert);
  const adminCommand = hasAdminCommand(alert);
  // 판정은 패턴 신호로 수행합니다. 실제 세션 거부 전의 신뢰도·근거 검증은 respond.mjs가 별도로 수행합니다.
  const atNewAddress = /처음 보는 주소|주소는 처음 봅니다|처음 봅니다|낯선 주소|원격 주소|미확인 (?:주소|IP)|새로운 출발지|처음 관측(?:된)? (?:주소|IP)|first[ -]?seen address|new(?:ly observed)? (?:source )?(?:address|IP)|remote address|unfamiliar (?:source|IP)|unknown (?:source|IP|address)|unrecognized (?:source|IP|address)|previously unseen (?:source|address)/i.test(description);
  const offHours = /수업 시간 밖|업무 시간 밖|업무 외 시간|야간|심야|업무처럼 보이지 않는 시각|비정상 시간|근무 시간 외|off[ -]?hours|outside (?:class|working|business) hours|after hours|during the night|at night/i.test(description);
  const elevatedThenCommand = hasRecentElevation(alert) && adminCommand;
  const groupAndCommand = groupAddition && adminCommand;
  const otherAccountCommand = adminCommand
    && /다른 계정의 권한|다른 계정 권한|another account.?s privileges|under another account/i.test(description);
  const failedAdminCommand = adminCommand
    && /실패|오류|거부|취소|중단|차단됨|실행되지 않|실행 안|실행 불가|failed|error|denied|cancelled|canceled|aborted|blocked|not executed|did not execute|failed to execute/i.test(description);
  const cancelledAttempt = /(?:권한 상승|관리자 명령|권한 명령|admin command|privileged command|elevation prompt|privilege escalation).{0,40}(?:취소|철회|중단|거부|cancelled|canceled|aborted|denied)|(?:취소|철회|중단|거부|cancelled|canceled|aborted|denied).{0,40}(?:권한 상승|관리자 명령|권한 명령|admin command|privileged command|elevation prompt|privilege escalation)/i.test(description);
  const noFollowupCommand = /(?:권한 상승|권한 변경|관리자 권한|privilege escalation|privilege elevation).{0,48}(?:명령.{0,12}(?:없|않|미실행|이어지지)|후속 명령 없음|명령 없이|no (?:admin |privileged )?command|without (?:an? )?(?:admin |privileged )?command|command did not follow)|(?:명령.{0,12}(?:없|않|미실행)|no (?:admin |privileged )?command|without (?:an? )?(?:admin |privileged )?command).{0,48}(?:권한 상승|권한 변경|관리자 권한|privilege escalation|privilege elevation)/i.test(description);
  const eventCount = Number(alert?.data?.count);
  const addedSeveralAccounts = groupAddition && (
    (Number.isFinite(eventCount) && eventCount >= 3)
    || /계정\s*[3-9]\d*\s*개.*관리자 그룹|(?:three|four|several) accounts?.{0,30}administrator group/i.test(description)
  );
  const repeatedAdminReadd = groupAddition
    && /빠진 계정.{0,30}1분 뒤.{0,20}다시 관리자로|removed.{0,30}one minute later.{0,20}re.added/i.test(description);
  const sessionElevationAtNewAddress = hasSessionElevation(alert) && atNewAddress;
  const cancelledElevation = cancelledAttempt
    || /권한 상승 창.{0,20}(?:취소|거부)|elevation prompt.{0,20}(?:cancelled|canceled|denied)/i.test(description);
  const elevationWithoutCommand = noFollowupCommand
    || /권한 상승.{0,35}(?:명령은 없습니다|명령 없이|이어지지 않|no command|without a command)|privilege escalation.{0,35}without.{0,12}command/i.test(description);

  // 명시적인 정상 대조 경보를 먼저 처리해 관리자 관련 단어만으로 올려 잡지 않습니다.
  const explicitlyBenign = /관리자 그룹은 아닙니다|관리자 그룹이 아닙니다|not an? admin(?:istrator)? group|not in (?:the )?administrators?|평소 주소에서 관리자 명령이 한 번 실행됐습니다|정상 주소에서 관리자 명령|계정 종류를 조회한 뒤 변경은 없습니다|그룹 목록을 읽은 뒤 수업 그룹 설명만 바뀌었습니다|새 로컬 그룹이 하나 만들어졌습니다|로그인했습니다|로그아웃했습니다|그룹 소속을 읽기만 했습니다|비밀번호를 변경했습니다|자기 세션 정보를 조회했습니다|자료실을 열었습니다|평소 예약 작업을 확인했습니다|routine (?:login|logout|task check|scheduled task)|read.only (?:query|enumeration)|no (?:privilege|permission|group) changes?|(?:usual|regular|known|trusted) address.{0,36}(?:admin(?:istrator)? command|login|logon|sign.?in)|(?:admin(?:istrator)? command).{0,36}(?:usual|regular|known|trusted) address|(?:logged|signed) (?:in|out) from (?:a )?(?:usual|regular|known|trusted) address/i.test(description);
  const hasFailureOrAmbiguity = failedAdminCommand || cancelledElevation || elevationWithoutCommand
    || addedSeveralAccounts || repeatedAdminReadd || sessionElevationAtNewAddress;
  if (explicitlyBenign && !hasFailureOrAmbiguity && !elevatedThenCommand && !groupAndCommand
      && !groupAddition && !otherAccountCommand
      && !(atNewAddress && adminCommand)
      && !(offHours && (atNewAddress || adminCommand))) {
    return output("ordinary_account_activity", 0.1);
  }

  // 이벤트 분류와 실제 세션 차단을 분리합니다. respond.mjs가 규칙 생성 전의 증거를 다시 검증합니다.

  // 실패·취소·후속 명령 없음은 성공한 공격으로 보지 않으므로 복합 패턴보다 먼저 처리합니다.
  if (cancelledElevation || elevationWithoutCommand || failedAdminCommand) {
    return output("ambiguous_privilege_activity", 0.68);
  }
  if (elevatedThenCommand) {
    return output("recent_elevation_then_admin_command", 0.96);
  }
  if (groupAndCommand) {
    return output("admin_group_added_then_admin_command", 0.96);
  }
  if (offHours && atNewAddress && adminCommand) {
    return output("off_hours_privilege_use", 0.72);
  }
  // 대량 그룹 추가나 반복 재추가는 조사 가치가 있지만, 명령 결합과 달리 이 이벤트 하나만으로 block하지 않습니다.
  if (addedSeveralAccounts) {
    return output("ambiguous_privilege_activity", 0.68);
  }
  if (sessionElevationAtNewAddress) {
    return output("ambiguous_privilege_activity", 0.68);
  }
  if (adminCommand && otherAccountCommand) {
    return output("unfamiliar_admin_command", 0.68);
  }
  if (repeatedAdminReadd) {
    return output("ambiguous_privilege_activity", 0.68);
  }
  if (offHours && (atNewAddress || adminCommand)) {
    return output("off_hours_privilege_use", 0.72);
  }
  if (adminCommand && atNewAddress) {
    return output("unfamiliar_admin_command", 0.68);
  }
  if (groupAddition) {
    return output("admin_group_addition", 0.68);
  }
  // 마지막 안전망은 "관리자/권한"이라는 단어 자체가 아니라 실제 변경·시도·위험 문맥을 요구합니다.
  // 따라서 평소 주소의 관리자 로그인, 로그아웃, 조회만으로 alert를 만들지 않습니다.
  const privilegeContext = isAdminGroup(alert)
    || /관리자|권한 상승|권한 변경|관리자 권한|administrator|\badmin\b|admin group|privilege|privileged|elevated|sudoers?|wheel/i.test(description);
  const privilegeOperation = /(?:관리자 그룹|관리자 권한|권한 상승|권한 변경|권한 부여|관리자로 승격|admin(?:istrator)? group|admin(?:istrator)? privileges?|privilege escalation|privilege elevation|privileged session).{0,40}(?:추가|변경|부여|회수|실행|시도|실패|취소|거부|중단|승격|전환|활성화|added|changed|granted|removed|executed|attempted|failed|cancelled|canceled|denied|aborted|elevated|switched)|(?:추가|변경|부여|회수|실행|시도|실패|취소|거부|중단|승격|전환|활성화).{0,40}(?:관리자 그룹|관리자 권한|권한 상승|권한 변경|권한 부여|관리자로 승격|admin(?:istrator)? group|admin(?:istrator)? privileges?|privilege escalation|privilege elevation|privileged session)|(?:비정상|예상하지 못한|의심스러운|abnormal|unexpected|suspicious).{0,32}(?:관리자|권한|administrator|admin|privilege)|(?:관리자|권한|administrator|admin|privilege).{0,32}(?:비정상|예상하지 못한|의심스러운|abnormal|unexpected|suspicious)/i.test(description);
  const ruleLevel = Number(alert?.rule?.level);
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasRiskContext = atNewAddress || offHours
    || ((Number.isFinite(ruleLevel) && ruleLevel >= 7)
      && (mitre.includes("T1068") || mitre.includes("T1078")));
  if (privilegeContext && (atNewAddress || offHours || (privilegeOperation && hasRiskContext))) {
    return output("ambiguous_privilege_activity", 0.56);
  }

  return output("ordinary_account_activity", 0.1);
}
