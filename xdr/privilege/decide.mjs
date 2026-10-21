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
      id: "recent_group_change_then_admin_command",
      name: "5분 내 관리자 그룹 변경과 관리자 명령",
      condition: "응답 단계에서 동일한 정규화 계정·동일 출발지의 관리자 그룹 변경과 관리자 명령 경보가 5분 안에 함께 나타나고, 두 경보의 규칙 수준·MITRE 근거가 유효할 때 거부 규칙 후보로 결합한다.",
      action: "confidence_threshold",
      confidence: 0.97,
      evidence: "T1078은 유효 계정 악용 맥락을, T1068은 권한 상승 결과인 관리자 명령의 악용 가능성을 뒷받침한다.",
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
  if (/관리자 그룹은 아닙니다|관리자 그룹이 아닙니다|관리자 그룹에 속하지 않|not an? admin(?:istrator)? group|not in (?:the )?administrators?|(?:not|never) added to (?:the )?(?:administrators?|admins?)/i.test(description)) {
    return false;
  }
  const raw = oneLine(alert?.data?.group);
  if (raw) {
    const normalized = raw.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim().toLowerCase();
    return /^(?:(?:domain|enterprise|builtin)\s+)?(?:administrators?|admins?)(?:\s+group)?$/.test(normalized)
      || /^(?:sudoers?|wheel|root|superusers|관리자|관리자그룹)$/.test(normalized)
      || /^S-1-5-32-544$/i.test(raw);
  }
  return /관리자 그룹|관리자 권한 그룹|administrators? group|admins? group|domain admins?|enterprise admins?|sudoers?|wheel group/i.test(description);
}

function hasAdminGroupAddition(alert) {
  const description = descriptionOf(alert);
  if (/관리자 그룹.{0,32}(?:추가되지 않았|추가되지 않음|추가 안 됨|추가 실패|추가가 실패|추가를 취소|변경 없음|없습니다|성공하지 않았)|(?:not|never) added to (?:the )?(?:administrators?|admins?|admin group)|failed to add.{0,24}(?:administrators?|admins?|admin group)|(?:administrators?|admins?|admin group).{0,24}(?:was not added|addition failed|was cancelled|was canceled)/i.test(description)) {
    return false;
  }
  return isAdminGroup(alert)
    && /추가|들어가|가입|다시 관리자|재등록|멤버로|added|joined|re-added|readded/i.test(description);
}

function hasAdminCommand(alert) {
  const description = descriptionOf(alert);
  if (/관리자 명령|권한 명령|관리자 권한.{0,24}명령|권한 상승.{0,24}명령|admin(?:istrator)? command|privileged command|elevated command|command.{0,24}(?:admin|elevat|privileg)|(?:sudo|runas)\s+(?:-\w+\s+)?[\w.-]+/i.test(description)) {
    return true;
  }
  const genericCommand = /명령.{0,20}(?:실행|수행|입력|호출)|(?:실행|수행|호출).{0,20}명령|(?:execute|executed|run|ran|invoke|invoked).{0,24}command|command.{0,24}(?:executed|run|invoked)/i.test(description);
  return genericCommand && (isAdminGroup(alert) || /관리자|권한 상승|권한 변경|administrator|privileg|elevat|sudo|runas/i.test(description));
}

function hasRecentElevation(alert) {
  const description = descriptionOf(alert);
  if (/권한 상승.{0,24}(?:성공하지 않았|실패|취소|거부)|관리자 권한.{0,24}(?:얻지 못|부여되지 않았|부여 실패|취소)|(?:not successfully elevated|failed to gain admin(?:istrator)? privileges|elevation (?:failed|was cancelled|was canceled|was denied))/i.test(description)) {
    return false;
  }
  return /방금 관리자가 된|새로 관리자가 된|관리자 권한을 얻|관리자 권한이 부여|관리자로 승격|권한 상승.{0,24}(?:성공|완료|됨)|권한 상승.{0,16}(?:직후|후 바로|후 곧바로)|just became an? administrator|newly elevated|elevated to (?:an? )?(?:admin|administrator)|granted (?:admin|administrator) privileges|became an? admin/i.test(description);
}

function hasSessionElevation(alert) {
  return /세션.{0,32}(?:관리자 권한|권한 상승|관리자로).{0,18}(?:바뀌|변경|전환|승격|되었|됨)|(?:관리자 권한|권한 상승).{0,24}(?:세션|계정).{0,18}(?:바뀌|변경|전환|승격)|session.{0,32}(?:admin|administrator|elevated).{0,18}(?:changed|switched|elevated|granted)/i.test(descriptionOf(alert));
}

function patternById(id) {
  return PATTERN_SPEC.patterns.find((pattern) => pattern.id === id)
    ?? PATTERN_SPEC.patterns[PATTERN_SPEC.patterns.length - 1];
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
  const offHours = /수업 시간 밖|업무 시간 밖|업무 외 시간|야간|심야|업무처럼 보이지 않는 시각|비정상 시간|근무 시간 외|off[ -]?hours|outside (?:class|working|business) hours|after hours|during the night|at night/i.test(description);
  const unfamiliarAddress = /처음 보는 주소|주소는 처음 봅니다|처음 봅니다|낯선 주소|미확인 (?:주소|IP)|새로운 출발지|처음 관측(?:된)? (?:주소|IP)|first[ -]?seen address|new(?:ly observed)? (?:source )?(?:address|IP)|unfamiliar (?:source|IP)|unknown (?:source|IP|address)|unrecognized (?:source|IP|address)|previously unseen (?:source|address)/i.test(description);
  const unfamiliarAdminCommand = /(?:(?:처음 보는|낯선|미확인|처음 관측(?:된)?|새로운)\s*.{0,16}(?:관리자 명령|권한 명령|관리자 권한 명령)|(?:관리자 명령|권한 명령|관리자 권한 명령).{0,16}(?:처음 보는|낯선|미확인|처음 관측(?:된)?|새로운)|(?:first[ -]?seen|unfamiliar|unrecognized|unknown|newly observed|novel).{0,32}(?:admin(?:istrator)? command|privileged command)|(?:admin(?:istrator)? command|privileged command).{0,32}(?:first[ -]?seen|unfamiliar|unrecognized|unknown|novel))/i.test(description);
  const explicitNonAdminGroup = /관리자 그룹은 아닙니다|관리자 그룹이 아닙니다|관리자 그룹에 속하지 않|not an? admin(?:istrator)? group|not in (?:the )?administrators?|(?:not|never) added to (?:the )?(?:administrators?|admins?)/i.test(description);
  const privilegeActionSignal = !explicitNonAdminGroup && /(?:관리자 그룹|관리자 권한|권한 상승|권한 변경|권한 부여|권한 회수|권한 사용|관리자로 승격|administrator group|admin group|administrator privileges|admin privileges|privilege escalation|privilege elevation|privilege change|privilege use|permission grant|role assignment).{0,44}(?:추가|변경|부여|회수|승격|전환|시도|실패|취소|거부|중단|실행|사용|사용했|added|changed|granted|revoked|elevated|switched|attempted|failed|cancelled|canceled|denied|aborted|executed|used|using)|(?:추가|변경|부여|회수|승격|전환|시도|실패|취소|거부|중단|실행|사용|사용했|added|changed|granted|revoked|elevated|switched|attempted|failed|cancelled|canceled|denied|aborted|executed|used|using).{0,44}(?:관리자 그룹|관리자 권한|권한 상승|권한 변경|권한 부여|권한 회수|권한 사용|관리자로 승격|administrator group|admin group|administrator privileges|admin privileges|privilege escalation|privilege elevation|privilege change|privilege use|permission grant|role assignment)/i.test(description);
  const elevatedThenCommand = hasRecentElevation(alert) && adminCommand;
  const groupAndCommand = groupAddition && adminCommand;
  const otherAccountCommand = adminCommand && /다른 계정의 권한|다른 계정 권한|another account.?s privileges|under another account/i.test(description);
  const failureLanguage = /실패|오류|거부|취소|중단|차단됨|실행되지 않|실행 안|실행 불가|추가되지 않았|추가 실패|권한을 얻지 못|부여되지 않았|failed|error|denied|cancelled|canceled|aborted|blocked|not executed|did not execute|failed to execute|failed to add|grant failed|not successfully/i.test(description);
  const failedAttempt = (adminCommand || groupAddition || hasRecentElevation(alert) || privilegeActionSignal) && failureLanguage;
  const cancelledAttempt = /(?:권한 상승|관리자 명령|권한 명령|admin command|privileged command|elevation prompt|privilege escalation).{0,40}(?:취소|철회|중단|거부|cancelled|canceled|aborted|denied)|(?:취소|철회|중단|거부|cancelled|canceled|aborted|denied).{0,40}(?:권한 상승|관리자 명령|권한 명령|admin command|privileged command|elevation prompt|privilege escalation)/i.test(description);
  const noFollowupCommand = /(?:권한 상승|권한 변경|관리자 권한|privilege escalation|privilege elevation).{0,48}(?:명령.{0,12}(?:없|않|미실행|이어지지)|후속 명령 없음|명령 없이|no (?:admin |privileged )?command|without (?:an? )?(?:admin |privileged )?command)|(?:명령.{0,12}(?:없|않|미실행)|no (?:admin |privileged )?command|without (?:an? )?(?:admin |privileged )?command).{0,48}(?:권한 상승|권한 변경|관리자 권한|privilege escalation|privilege elevation)/i.test(description);
  const eventCount = Number(alert?.data?.count);
  const addedSeveralAccounts = groupAddition && (
    (Number.isFinite(eventCount) && eventCount >= 3)
    || /계정\s*[3-9]\d*\s*개.*관리자 그룹|(?:three|four|several) accounts?.{0,30}administrator group/i.test(description)
  );
  const repeatedAdminReadd = groupAddition && /빠진 계정.{0,30}1분 뒤.{0,20}다시 관리자로|removed.{0,30}one minute later.{0,20}re.added/i.test(description);
  const sessionElevationAtNewAddress = hasSessionElevation(alert) && unfamiliarAddress;
  const cancelledElevation = cancelledAttempt || /권한 상승 창.{0,20}(?:취소|거부)|elevation prompt.{0,20}(?:cancelled|canceled|denied)/i.test(description);

  if (cancelledElevation || noFollowupCommand || failedAttempt) {
    return output("ambiguous_privilege_activity", 0.68);
  }
  // 명확한 공격은 행위 조합 자체로 판정합니다. 출발지·규칙 수준·MITRE·identity 메타데이터는 필수 조건이 아닙니다.
  if (elevatedThenCommand) {
    return output("recent_elevation_then_admin_command", 0.96);
  }
  if (groupAndCommand) {
    return output("admin_group_added_then_admin_command", 0.96);
  }
  // 시간대와 낯선 주소·명령은 의심 신호일 뿐, 단독으로 공격 확정(block)하지 않습니다.
  if (offHours && (adminCommand || groupAddition || hasSessionElevation(alert) || hasRecentElevation(alert) || privilegeActionSignal)) {
    return output("off_hours_privilege_use", 0.72);
  }
  if (addedSeveralAccounts || repeatedAdminReadd || sessionElevationAtNewAddress) {
    return output("ambiguous_privilege_activity", 0.68);
  }
  if (unfamiliarAdminCommand || otherAccountCommand || (adminCommand && unfamiliarAddress)) {
    return output("unfamiliar_admin_command", 0.68);
  }
  if (groupAddition) {
    return output("admin_group_addition", 0.68);
  }
  // 권한 상승/변경 정황은 있지만 성공한 명령 결합은 확인되지 않으면 조사 알림으로 남깁니다.
  if (hasRecentElevation(alert) || hasSessionElevation(alert) || privilegeActionSignal) {
    return output("ambiguous_privilege_activity", 0.68);
  }
  return output("ordinary_account_activity", 0.1);
}
