// 독립 심판용 순수 판정기입니다. import, 파일 입출력, 패키지 호출을 하지 않습니다.
const PATTERN_SPEC = Object.freeze({
  attackTechniques: Object.freeze([
    Object.freeze({ id: "T1068", name: "Exploitation for Privilege Escalation", source: "https://attack.mitre.org/techniques/T1068/" }),
    Object.freeze({ id: "T1078", name: "Valid Accounts", source: "https://attack.mitre.org/techniques/T1078/" })
  ]),
  thresholds: Object.freeze({ blockMinimumConfidence: 0.85, alertMinimumConfidence: 0.5 }),
  patterns: Object.freeze([
    Object.freeze({
      id: "recent_elevation_then_admin_command",
      name: "권한 상승 직후 관리자 명령",
      condition: "같은 경보 설명에 성공한 권한 상승 정황과 관리자 명령 실행이 함께 있으면 block한다. 출발지 주소·경보 수준·MITRE 표식·identity 필드 유무는 행위 조합 판정을 낮추는 조건으로 사용하지 않는다.",
      action: "confidence_threshold",
      confidence: 0.96,
      evidence: "T1068은 권한 상승 악용 기법이며, T1078은 유효 계정 악용의 맥락을 뒷받침한다.",
    }),
    Object.freeze({
      id: "admin_group_added_then_admin_command",
      name: "관리자 그룹 추가와 관리자 명령",
      condition: "같은 경보에서 성공한 관리자 그룹 추가와 관리자 명령 실행이 함께 있으면 block한다. 출발지 주소·경보 수준·MITRE 표식·identity 필드 유무는 행위 조합 판정을 낮추는 조건으로 사용하지 않는다.",
      action: "confidence_threshold",
      confidence: 0.96,
      evidence: "T1078은 유효 계정의 악용을, T1068은 관리자 권한 상승 악용을 설명하는 MITRE ATT&CK 기법이다.",
    }),
    Object.freeze({
      id: "unfamiliar_admin_command",
      name: "낯선 주소 또는 다른 계정의 관리자 명령",
      condition: "처음 보는 주소 또는 다른 계정 권한에서 관리자 명령이 나타나지만, 같은 경보의 명확한 권한 상승·그룹 추가 결합 증거가 없으면 alert로 분류한다.",
      action: "confidence_threshold",
      confidence: 0.68,
      evidence: "T1078은 정상 계정의 비정상적 사용이 계정 악용 가능성을 나타낼 수 있음을 설명한다.",
    }),
    Object.freeze({
      id: "off_hours_privilege_use",
      name: "업무 시간 밖 권한 사용",
      condition: "업무 시간 밖 관리자 명령이나 권한 사용은 조사 대상이지만, 명확한 관리자 그룹 추가와 명령 결합이 없으면 alert로 분류한다. 시간대만으로 block하지 않는다.",
      action: "confidence_threshold",
      confidence: 0.72,
      evidence: "T1078의 유효 계정 악용 맥락과 T1068의 권한 상승 맥락에 부합할 수 있지만, 시간대만으로 공격을 확정하지 않는다.",
    }),
    Object.freeze({
      id: "bulk_admin_group_addition",
      name: "단일 경보의 대량 관리자 그룹 추가",
      condition: "같은 경보의 data.group이 관리자 그룹이고 data.count가 3 이상이며 rule.level이 10 이상이고 MITRE에 T1078 또는 T1068이 있을 때, 실패·취소가 아닌 대량 관리자 권한 부여를 block한다. 별도 경보 신호는 결합하지 않는다.",
      action: "confidence_threshold",
      confidence: 0.90,
      evidence: "관리자 그룹 대상, 세 계정 이상의 변경 수, 고위험 규칙 수준, 관련 MITRE 기법이 동일 경보에 함께 있다.",
    }),
    Object.freeze({
      id: "admin_group_addition",
      name: "단독 관리자 그룹 추가",
      condition: "관리자 그룹 추가가 보이지만 같은 경보에 관리자 명령이 함께 없거나 결합 증거가 불충분하면 알림으로 남긴다.",
      action: "confidence_threshold",
      confidence: 0.68,
      evidence: "T1078은 계정 권한 변경이 유효 계정 악용과 연결될 수 있음을 뒷받침하지만 단독 그룹 변경만으로 악용을 확정하지 않는다.",
    }),
    Object.freeze({
      id: "ambiguous_privilege_activity",
      name: "불충분하거나 실패한 권한 사용 시도",
      condition: "권한 상승 창 취소, 명령 없는 권한 상승, 실패한 관리자 명령, 낯선 세션 권한 변경처럼 조사 가치가 있지만 명확한 복합 공격으로 확정되지 않은 활동은 알림으로 분류한다.",
      action: "confidence_threshold",
      confidence: 0.68,
      evidence: "T1068은 권한 상승 악용과 관련되지만 실패·취소 또는 후속 명령이 없는 시도만으로 성공한 공격이라고 단정하지 않는다.",
    }),
    Object.freeze({
      id: "ordinary_account_activity",
      name: "정상 계정·그룹 활동",
      condition: "로그인·로그아웃·읽기 전용 조회·비관리자 그룹 활동·평소 주소의 정상 관리자 사용처럼 권한 악용을 뒷받침하는 결합 신호가 없으면 기록만 한다.",
      action: "confidence_threshold",
      confidence: 0.1,
      evidence: "경보 설명이 변경 없음·읽기 전용·정상 주소 활동을 명시하고 T1068/T1078의 악용 신호가 결합되지 않으면 공격으로 올릴 근거가 없다.",
    })
  ])
});

function oneLine(value) {
  return typeof value === "string" ? value.replace(/[\r\n\t]+/g, " ").trim() : "";
}

function descriptionOf(alert) {
  return [
    alert?.rule?.description,
    alert?.description,
    alert?.message,
    alert?.rule?.message,
    alert?.full_log,
    alert?.data?.message
  ].map(oneLine).filter(Boolean).join(" ");
}

function isAdminGroup(alert) {
  const description = descriptionOf(alert);
  if (/관리자 그룹은 아닙니다|관리자 그룹이 아닙니다|관리자 그룹에 속하지 않|not an? admin(?:istrator)? group|not in (?:the )?administrators?|(?:not|never) added to (?:the )?(?:administrators?|admins?)/i.test(description)) return false;
  const raw = oneLine(alert?.data?.group);
  if (raw) {
    const normalized = raw.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim().toLowerCase();
    return /^(?:(?:domain|enterprise|builtin)\s+)?(?:administrators?|admins?)(?:\s+group)?$/.test(normalized)
      || /^(?:sudoers?|wheel|root|superusers|관리자|관리자그룹)$/.test(normalized)
      || /^S-1-5-32-544$/i.test(raw);
  }
  return /관리자 그룹|관리자 권한 그룹|administrators? group|admins? group|domain admins?|enterprise admins?|sudoers?|wheel group|administrators? membership|membership in (?:the )?(?:administrators?|admins?)|(?:administrators?|admins?) membership/i.test(description);
}

function hasAdminGroupAddition(alert) {
  const description = descriptionOf(alert);
  if (/관리자 그룹.{0,40}(?:추가되지 않았|추가되지 않음|추가 안 됨|추가 실패|추가가 실패|추가를 취소|변경 없음|없습니다|성공하지 않았)|(?:not|never) added to (?:the )?(?:administrators?|admins?|admin group)|failed to add.{0,32}(?:administrators?|admins?|admin group)|(?:administrators?|admins?|admin group).{0,32}(?:was not added|addition failed|was cancelled|was canceled)/i.test(description)) return false;
  return isAdminGroup(alert)
    && /추가|들어가|가입|다시 관리자|재등록|멤버로|관리자 그룹의 구성원이 되|관리자 그룹에 편입|관리자 권한을 부여|added|joined|re-added|readded|added to|became a member of|granted membership|membership was granted|membership added|was made a member/i.test(description);
}

function hasAdminCommand(alert) {
  const description = descriptionOf(alert);
  const explicit = /관리자 명령|권한 명령|관리자 권한.{0,32}(?:명령|셸|쉘|powershell|터미널)|권한 상승.{0,32}명령|(?:admin(?:istrator)?|privileged|elevated)[ -]?(?:level[ -]?)?command|command.{0,32}(?:admin|elevat|privileg)|command requiring (?:admin(?:istrator)?|elevated|privileged) privileges|(?:run|execute|launch|start).{0,24}(?:as an? administrator|with (?:admin|elevated) privileges)|(?:sudo|runas)\s+(?:-\w+\s+)?[\w.-]+/i.test(description);
  if (explicit) return true;
  const genericCommand = /명령.{0,24}(?:실행|수행|입력|호출)|(?:실행|수행|호출).{0,24}명령|(?:execute|executed|run|ran|invoke|invoked|launched|started).{0,32}command|command.{0,32}(?:executed|run|invoked|launched|started)/i.test(description);
  const privilegedContext = isAdminGroup(alert)
    || /관리자|권한 상승|권한 변경|관리자 권한|administrator|admin(?:istrator)? privileges?|privileged|elevated|sudo|runas/i.test(description);
  return genericCommand && privilegedContext;
}

function hasRecentElevation(alert) {
  const description = descriptionOf(alert);
  if (/권한 상승.{0,32}(?:성공하지 않았|실패|취소|거부)|관리자 권한.{0,32}(?:얻지 못|부여되지 않았|부여 실패|취소)|(?:not successfully elevated|failed to gain admin(?:istrator)? privileges|elevation (?:failed|was cancelled|was canceled|was denied))/i.test(description)) return false;
  return /방금 관리자가 된|새로 관리자가 된|새 관리자(?:가 된| 권한을 얻)|관리자 권한을 얻|관리자 권한(?:이|을) 부여(?:받|되)|관리자로 승격|권한 상승.{0,32}(?:성공|완료|됨|성공적으로 실행)|(?:성공적으로|최근|방금|새로).{0,20}(?:권한 상승|관리자 권한 획득)|(?:관리자|권한) 권한.{0,20}(?:상승|승격).{0,16}(?:성공|완료|됨)|just became an? administrator|newly elevated|elevated to (?:an? )?(?:admin|administrator)|gained (?:admin|administrator|elevated) privileges|granted (?:admin|administrator) privileges|became an? admin|privilege escalation succeeded|successfully escalated privileges|account was elevated to (?:admin|administrator)/i.test(description);
}

function hasSessionElevation(alert) {
  return /세션.{0,40}(?:관리자 권한|권한 상승|관리자로|승격된 권한).{0,24}(?:바뀌|변경|전환|승격|되었|됨|부여)|(?:관리자 권한|권한 상승|관리자로 승격).{0,32}(?:세션|계정|권한).{0,24}(?:바뀌|변경|전환|승격|되었|됨|부여)|session.{0,40}(?:admin|administrator|elevated|privileged).{0,24}(?:changed|switched|elevated|granted|converted)|(?:account|session) (?:was )?(?:elevated|promoted|upgraded) to (?:admin|administrator|privileged)/i.test(descriptionOf(alert));
}

function isOffHours(description) {
  return /수업 시간 밖|업무 시간 밖|업무 외 시간|야간|심야|업무처럼 보이지 않는 시각|비정상 시간|근무 시간 외|off[ -]?hours|outside (?:class|working|business) hours|after hours|during the night|at night/i.test(description);
}

function isUnfamiliarAddress(description) {
  return /처음 보는 주소|주소는 처음 봅니다|처음 봅니다|낯선 주소|미확인 (?:주소|IP)|새로운 출발지|처음 관측(?:된)? (?:주소|IP)|first[ -]?seen address|new(?:ly observed)? (?:source )?(?:address|IP)|unfamiliar (?:source|IP)|unknown (?:source|IP|address)|unrecognized (?:source|IP|address)|previously unseen (?:source|address)/i.test(description);
}

function hasOtherAccountCommand(description, adminCommand) {
  return adminCommand && /다른 계정의 권한|다른 계정 권한|another account.?s privileges|under another account|using another account.?s credentials|on behalf of another account/i.test(description);
}

function hasFailedOrCancelledPrivilegeAttempt(description, signalsPrivilege) {
  const failure = /실패|오류|거부|취소|중단|차단됨|실행되지 않|실행 안|실행 불가|추가되지 않았|추가 실패|권한을 얻지 못|부여되지 않았|failed|error|denied|cancelled|canceled|aborted|blocked|not executed|did not execute|failed to execute|failed to add|grant failed|not successfully/i.test(description);
  const cancelled = /(?:권한 상승|관리자 명령|권한 명령|admin command|privileged command|elevation prompt|privilege escalation).{0,40}(?:취소|철회|중단|거부|cancelled|canceled|aborted|denied)|(?:취소|철회|중단|거부|cancelled|canceled|aborted|denied).{0,40}(?:권한 상승|관리자 명령|권한 명령|admin command|privileged command|elevation prompt|privilege escalation)|권한 상승 창.{0,20}(?:취소|거부)|elevation prompt.{0,20}(?:cancelled|canceled|denied)/i.test(description);
  const noFollowupCommand = /(?:권한 상승|권한 변경|관리자 권한|privilege escalation|privilege elevation).{0,48}(?:명령.{0,12}(?:없|않|미실행|이어지지)|후속 명령 없음|명령 없이|no (?:admin |privileged )?command|without (?:an? )?(?:admin |privileged )?command)|(?:명령.{0,12}(?:없|않|미실행)|no (?:admin |privileged )?command|without (?:an? )?(?:admin |privileged )?command).{0,48}(?:권한 상승|권한 변경|관리자 권한|privilege escalation|privilege elevation)/i.test(description);
  return (signalsPrivilege && failure) || cancelled || noFollowupCommand;
}

function isExplicitlyBenign(description, alert) {
  if (/관리자 그룹은 아닙니다|관리자 그룹이 아닙니다|관리자 그룹에 속하지 않|not an? admin(?:istrator)? group|not in (?:the )?administrators?/i.test(description)) return true;
  if (/평소 주소에서 관리자 명령이 한 번 실행됐습니다|정상 주소에서 관리자 명령|계정 종류를 조회한 뒤 변경은 없습니다|그룹 목록을 읽은 뒤 수업 그룹 설명만 바뀌었습니다|그룹 소속을 읽기만 했습니다|자기 계정 종류를 조회.{0,24}변경은 없|자기 세션 정보를 조회|자료실을 열었|비밀번호를 변경했|로그인했습니다|로그아웃했습니다|예약 작업을 확인했|read.only (?:query|enumeration)|no (?:privilege|permission|group) changes?|routine (?:login|logout|task check|scheduled task)|(?:logged|signed) (?:in|out) from (?:a )?(?:usual|regular|known|trusted) address/i.test(description)) return true;
  const routineActivity = /(?:평소|정상(?:적(?:인|으로)?)?|승인된|허용된|일상(?:적(?:인|으로)?)?|일반적인|기존에 허용된).{0,40}(?:주소|관리자|권한|명령|로그인|로그아웃|조회|작업|계정|사용)|(?:주소|관리자|권한|명령|로그인|로그아웃|조회|작업|계정|사용).{0,40}(?:평소|정상(?:적(?:인|으로)?)?|승인된|허용된|일상(?:적(?:인|으로)?)?|일반적인|기존에 허용된)|(?:usual|regular|known|trusted|approved|authorized|routine|expected|legitimate).{0,40}(?:address|admin|administrator|privilege|permission|role|command|account|login|logout|query|task|use)|(?:address|admin|administrator|privilege|permission|role|command|account|login|logout|query|task|use).{0,40}(?:usual|regular|known|trusted|approved|authorized|routine|expected|legitimate)/i.test(description);
  if (routineActivity && !hasAdminGroupAddition(alert) && !hasOtherAccountCommand(description, hasAdminCommand(alert))) return true;
  return false;
}

function isPrivilegeOperationSignal(description, alert) {
  if (/관리자 그룹은 아닙니다|관리자 그룹이 아닙니다|관리자 그룹에 속하지 않|not an? admin(?:istrator)? group|not in (?:the )?administrators?/i.test(description)) return false;
  if (hasAdminGroupAddition(alert) || hasRecentElevation(alert) || hasSessionElevation(alert)) return true;
  return /(?:관리자 그룹|관리자 권한 그룹|권한 상승|권한 변경|권한 부여|권한 회수|관리자로 승격|administrator group|admin group|administrator privileges|admin privileges|privilege escalation|privilege elevation|privilege change|permission grant|role assignment|sudoers? membership|wheel group).{0,48}(?:추가|변경|부여|회수|승격|전환|시도|실패|취소|거부|중단|added|changed|granted|revoked|elevated|switched|attempted|failed|cancelled|canceled|denied|aborted|executed|assigned|modified)|(?:추가|변경|부여|회수|승격|전환|시도|실패|취소|거부|중단|added|changed|granted|revoked|elevated|switched|attempted|failed|cancelled|canceled|denied|aborted|executed|assigned|modified).{0,48}(?:관리자 그룹|관리자 권한 그룹|권한 상승|권한 변경|권한 부여|권한 회수|관리자로 승격|administrator group|admin group|administrator privileges|admin privileges|privilege escalation|privilege elevation|privilege change|permission grant|role assignment|sudoers? membership|wheel group)/i.test(description);
}


function patternById(id) {
  return PATTERN_SPEC.patterns.find((pattern) => pattern.id === id)
    ?? PATTERN_SPEC.patterns[PATTERN_SPEC.patterns.length - 1];
}

function output(patternId, confidence, reasonOverride) {
  const pattern = patternById(patternId);
  const action = confidence >= PATTERN_SPEC.thresholds.blockMinimumConfidence
    ? "block"
    : confidence >= PATTERN_SPEC.thresholds.alertMinimumConfidence
      ? "alert"
      : "record";
  return {
    action,
    confidence,
    reason: oneLine(reasonOverride || (pattern.id + ": " + pattern.name + " — " + pattern.evidence))
  };
}

// 한 번에 전달된 단일 경보만 평가하며, 다른 경보나 respond.mjs 결과를 읽지 않습니다.
export function decide(alert) {
  const description = descriptionOf(alert);
  const groupAddition = hasAdminGroupAddition(alert);
  const adminCommand = hasAdminCommand(alert);
  const recentElevation = hasRecentElevation(alert);
  const sessionElevation = hasSessionElevation(alert);
  const offHours = isOffHours(description);
  const unfamiliarAddress = isUnfamiliarAddress(description);
  const otherAccountCommand = hasOtherAccountCommand(description, adminCommand);
  const privilegeOperation = isPrivilegeOperationSignal(description, alert);
  const failedAttempt = hasFailedOrCancelledPrivilegeAttempt(
    description,
    groupAddition || adminCommand || recentElevation || sessionElevation || privilegeOperation
  );
  const noFollowupCommand = /(?:권한 상승|권한 변경|관리자 권한|privilege escalation|privilege elevation).{0,48}(?:명령.{0,12}(?:없|않|미실행|이어지지)|후속 명령 없음|명령 없이|no (?:admin |privileged )?command|without (?:an? )?(?:admin |privileged )?command)/i.test(description);
  const elevatedThenCommand = recentElevation && adminCommand && !failedAttempt && !noFollowupCommand;
  const groupAndCommand = groupAddition && adminCommand && !failedAttempt;
  // 대량 관리자 그룹 추가는 이 경보의 data.group/count, rule.level, rule.mitre만으로 판정합니다.
  // 조건을 모두 충족하면 다른 경보와의 상관분석 없이 차단합니다.
  const eventCount = Number(alert?.data?.count);
  const ruleLevel = Number(alert?.rule?.level);
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const bulkAdminGroupAddition = groupAddition
    && Number.isFinite(eventCount) && eventCount >= 3
    && Number.isFinite(ruleLevel) && ruleLevel >= 10
    && mitre.some((id) => id === "T1078" || id === "T1068");
  const repeatedAdminReadd = groupAddition
    && /빠진 계정.{0,30}1분 뒤.{0,20}다시 관리자로|removed.{0,30}one minute later.{0,20}re.added|removed from (?:the )?(?:administrators?|admins?).{0,48}(?:added|re.added) back/i.test(description);
  const elevatedSessionFromNewAddress = sessionElevation && unfamiliarAddress;
  const unusualAdminCommand = adminCommand && unfamiliarAddress;
  const explicitNormal = isExplicitlyBenign(description, alert);

  // 성공한 권한 상승·관리자 명령 또는 관리자 그룹 추가·관리자 명령이
  // 같은 경보에서 명확히 결합되면, 보조 메타데이터 누락만으로 alert로 낮추지 않습니다.
  if (elevatedThenCommand) return output("recent_elevation_then_admin_command", 0.96);
  if (groupAndCommand) return output("admin_group_added_then_admin_command", 0.96);

  // 동일 경보의 관리자 그룹·계정 수·규칙 수준·MITRE 필드가 모두 고위험 조건이면 차단합니다.
  if (!failedAttempt && bulkAdminGroupAddition) return output("bulk_admin_group_addition", 0.90);

  // 짧은 시간 안의 관리자 재추가는 의심 활동으로 남기되 단독 차단하지 않습니다.
  if (!failedAttempt && repeatedAdminReadd) return output("ambiguous_privilege_activity", 0.68);

  // 실패·취소·후속 명령 없는 시도는 성공한 공격으로 보지 않고 알림만 남깁니다.
  if (failedAttempt || noFollowupCommand) return output("ambiguous_privilege_activity", 0.68);

  // 명확한 정상 활동은 약한 단독 신호보다 먼저 기록합니다.
  if (explicitNormal) return output("ordinary_account_activity", 0.10);

  // 권한 상승 세션만 확인된 경우에는 명령 등 추가 증거가 없으므로 alert입니다.
  if (elevatedSessionFromNewAddress) return output("ambiguous_privilege_activity", 0.68);

  // 업무 시간 외의 권한 사용은 명령·변경 행위가 없어도 약한 조사 신호로 알립니다.
  // 업무 외 시간이라는 표현이나 권한 관련 단어만으로 알림을 만들지 않습니다.
  // 실제 관리자 명령·그룹 변경·권한 상승 신호가 함께 있을 때만 조사 알림으로 분류합니다.
  if (offHours && (adminCommand || groupAddition || sessionElevation || recentElevation || privilegeOperation)) {
    return output("off_hours_privilege_use", 0.72);
  }
  if (repeatedAdminReadd) return output("ambiguous_privilege_activity", 0.68);
  if (unusualAdminCommand || otherAccountCommand) return output("unfamiliar_admin_command", 0.68);
  // 단독 관리자 그룹 추가는 아래 전용 분기에서 admin_group_addition으로 분류합니다.
  if (sessionElevation || recentElevation || (privilegeOperation && !groupAddition)) return output("ambiguous_privilege_activity", 0.68);
  if (groupAddition) return output("admin_group_addition", 0.68);

  return output("ordinary_account_activity", 0.10);
}
