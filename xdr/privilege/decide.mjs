// 독립 심판용 순수 판정기입니다. import, 파일 입출력, 패키지 호출을 하지 않습니다.
// 패턴 ID·조건·확신도·근거는 patterns.json과 동일하게 유지합니다. 상관분석은 respond.mjs의 책임입니다.
const PATTERN_SPEC = Object.freeze({
  attackTechniques: Object.freeze([
    {
      "id": "T1068",
      "name": "Exploitation for Privilege Escalation",
      "source": "https://attack.mitre.org/techniques/T1068/"
    },
    {
      "id": "T1078",
      "name": "Valid Accounts",
      "source": "https://attack.mitre.org/techniques/T1078/"
    }
  ]),
  thresholds: Object.freeze({
    "blockMinimumConfidence": 0.85,
    "alertMinimumConfidence": 0.5,
    "blockMinimumRuleLevel": 10,
    "correlationWindowSeconds": 300,
    "sessionRuleTtlSeconds": 900
  }),
  patterns: Object.freeze([
    Object.freeze({
      "id": "recent_elevation_then_admin_command",
      "name": "권한 상승 직후 관리자 명령",
      "condition": "같은 경보에 성공한 권한 상승과 실제 실행된 관리자 명령이 함께 있어야 하며, rule.level 10 이상·유효한 출발지 IP·T1068/T1078 근거·trusted-directory 출처의 identity.subjectId가 모두 있을 때만 block한다.",
      "action": "confidence_threshold",
      "confidence": 0.96,
      "evidence": "T1068은 권한 상승 악용 기법이며, T1078은 유효 계정 악용의 맥락을 뒷받침한다."
    }),
    Object.freeze({
      "id": "admin_group_added_then_admin_command",
      "name": "관리자 그룹 추가와 관리자 명령",
      "condition": "같은 경보에 성공한 관리자 그룹 추가와 실제 실행된 관리자 명령이 함께 있어야 하며, rule.level 10 이상·유효한 출발지 IP·T1068/T1078 근거·trusted-directory 출처의 identity.subjectId가 모두 있을 때만 block한다.",
      "action": "confidence_threshold",
      "confidence": 0.96,
      "evidence": "T1078은 유효 계정의 악용을, T1068은 관리자 권한 상승 악용을 설명하는 MITRE ATT&CK 기법이다."
    }),
    Object.freeze({
      "id": "bulk_admin_group_addition",
      "name": "단일 경보의 대량 관리자 그룹 추가",
      "condition": "같은 경보의 data.group이 관리자 그룹을 가리키고 data.count가 3 이상이어야 한다. 또한 rule.level 10 이상·유효한 출발지 IP·T1078/T1068 근거·trusted-directory 출처의 identity.subjectId가 모두 있을 때만 block한다. 실패·취소된 변경은 제외하며 별도 경보 신호는 결합하지 않는다.",
      "action": "confidence_threshold",
      "confidence": 0.9,
      "evidence": "관리자 그룹 대상, 세 계정 이상의 변경 수, 고위험 규칙 수준, 관련 MITRE 기법이 동일 경보에 함께 있다."
    }),
    Object.freeze({
      "id": "recent_group_change_then_admin_command",
      "name": "5분 내 관리자 그룹 변경과 관리자 명령",
      "condition": "응답 단계에서 동일한 정규화 계정·동일 출발지의 관리자 그룹 변경과 관리자 명령 경보가 5분 안에 함께 나타나고, 두 경보의 규칙 수준·MITRE 근거가 유효할 때 거부 규칙 후보로 결합한다.",
      "action": "confidence_threshold",
      "confidence": 0.97,
      "evidence": "T1078은 유효 계정 악용 맥락을, T1068은 권한 상승 결과인 관리자 명령의 악용 가능성을 뒷받침한다."
    }),
    Object.freeze({
      "id": "unfamiliar_admin_command",
      "name": "낯선 주소 또는 다른 계정의 관리자 명령",
      "condition": "처음 보는 주소 또는 다른 계정 권한에서 관리자 명령이 나타나지만, 같은 경보의 명확한 권한 상승·그룹 추가 결합 증거가 없으면 alert로 분류한다.",
      "action": "confidence_threshold",
      "confidence": 0.68,
      "evidence": "T1078은 정상 계정의 비정상적 사용이 계정 악용 가능성을 나타낼 수 있음을 설명한다."
    }),
    Object.freeze({
      "id": "off_hours_privilege_use",
      "name": "업무 시간 밖 권한 사용",
      "condition": "업무 시간 밖 관리자 명령이나 권한 사용은 조사 대상이지만, 명확한 관리자 그룹 추가와 명령 결합이 없으면 alert로 분류한다. 시간대만으로 block하지 않는다.",
      "action": "confidence_threshold",
      "confidence": 0.72,
      "evidence": "T1078의 유효 계정 악용 맥락과 T1068의 권한 상승 맥락에 부합할 수 있지만, 시간대만으로 공격을 확정하지 않는다."
    }),
    Object.freeze({
      "id": "admin_group_addition",
      "name": "단독 관리자 그룹 추가",
      "condition": "관리자 그룹 추가가 보이지만 같은 경보에 관리자 명령이 함께 없거나 결합 증거가 불충분하면 알림으로 남긴다.",
      "action": "confidence_threshold",
      "confidence": 0.68,
      "evidence": "T1078은 계정 권한 변경이 유효 계정 악용과 연결될 수 있음을 뒷받침하지만 단독 그룹 변경만으로 악용을 확정하지 않는다."
    }),
    Object.freeze({
      "id": "ambiguous_privilege_activity",
      "name": "불충분하거나 실패한 권한 사용 시도",
      "condition": "권한 상승 창 취소, 명령 없는 권한 상승, 실패한 관리자 명령, 낯선 세션 권한 변경처럼 조사 가치가 있지만 명확한 복합 공격으로 확정되지 않은 활동은 알림으로 분류한다.",
      "action": "confidence_threshold",
      "confidence": 0.68,
      "evidence": "T1068은 권한 상승 악용과 관련되지만 실패·취소 또는 후속 명령이 없는 시도만으로 성공한 공격이라고 단정하지 않는다."
    }),
    Object.freeze({
      "id": "ordinary_account_activity",
      "name": "정상 계정·그룹 활동",
      "condition": "로그인·로그아웃·읽기 전용 조회·비관리자 그룹 활동·평소 주소의 정상 관리자 사용처럼 권한 악용을 뒷받침하는 결합 신호가 없으면 기록만 한다.",
      "action": "confidence_threshold",
      "confidence": 0.1,
      "evidence": "경보 설명이 변경 없음·읽기 전용·정상 주소 활동을 명시하고 T1068/T1078의 악용 신호가 결합되지 않으면 공격으로 올릴 근거가 없다."
    })
  ])
});

function oneLine(value) {
  if (typeof value === "string") return value.replace(/[\r\n\t]+/g, " ").trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

function normalize(value) {
  return oneLine(value).replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim().toLowerCase();
}

function descriptionOf(alert) {
  const fields = [
    alert?.rule?.description, alert?.rule?.message, alert?.description,
    alert?.message, alert?.full_log, alert?.action, alert?.operation,
    alert?.event, alert?.data?.message, alert?.data?.action,
    alert?.data?.operation, alert?.data?.event, alert?.data?.event_name,
    alert?.data?.command, alert?.data?.command_line, alert?.data?.process,
    alert?.data?.status, alert?.data?.outcome, alert?.data?.result
  ];
  return fields.map(normalize).filter(Boolean).join(" ");
}

function statusOf(alert) {
  return [
    alert?.status, alert?.outcome, alert?.result, alert?.success,
    alert?.data?.status, alert?.data?.outcome, alert?.data?.result,
    alert?.data?.success, alert?.data?.execution_status
  ].map(normalize).filter(Boolean).join(" ");
}

function isAdminGroupName(value) {
  const name = normalize(value);
  return /^(?:(?:domain|enterprise|builtin)\s+)?(?:administrators?|admins?)(?:\s+group)?$/.test(name)
    || /^(?:sudoers?|wheel|root|superusers?|관리자|관리자 그룹)$/.test(name)
    || /^s-1-5-32-544$/i.test(name);
}

function isExplicitlyNonAdminGroup(text) {
  return /(?:관리자|administrator|admin).{0,18}(?:그룹|group|membership|멤버십).{0,14}(?:아닙니다|아니|아닌|속하지 않|아니라고)|(?:not|never)\s+(?:an?\s+)?(?:administrator|admin)(?:istrator)?\s*(?:group|membership)?|not in (?:the )?(?:administrators?|admins?)/i.test(text);
}

function isAdminGroup(alert, text = descriptionOf(alert)) {
  if (isExplicitlyNonAdminGroup(text)) return false;
  const rawGroup = oneLine(alert?.data?.group ?? alert?.data?.target_group ?? alert?.group);
  if (rawGroup) return isAdminGroupName(rawGroup);
  return /(?:관리자|administrator|admins?).{0,24}(?:그룹|group|membership|멤버십|구성원|role)|(?:그룹|group|membership|멤버십).{0,24}(?:관리자|administrator|admins?)|sudoers?|wheel group|superuser group/i.test(text);
}

function hasAddVerb(text) {
  return /추가|더하|들어가|들어오|가입|편입|등록|다시.{0,16}관리자|관리자로.{0,12}(?:되|들어오|복귀)|구성원.{0,12}(?:되|추가)|멤버.{0,12}(?:되|추가)|added?|addition|joined?|re.added|added back|became a member|membership.{0,16}(?:grant|add)|granted membership|assigned to/i.test(text);
}

function hasRemoveVerb(text) {
  return /제거|삭제|빠진|빠졌|빠져|빠지|탈퇴|회수|해제|제외|removed?|deleted?|revoked?|dropped from|removed from|left the group|membership.{0,16}(?:revoked|removed)/i.test(text);
}

function hasAdminGroupAddition(alert, text = descriptionOf(alert)) {
  return isAdminGroup(alert, text) && hasAddVerb(text);
}

function hasAdminGroupRemoval(alert, text = descriptionOf(alert)) {
  return isAdminGroup(alert, text) && hasRemoveVerb(text);
}

function hasCommandMention(text) {
  return /명령|command|shell|powershell|cmd(?:\.exe)?|sudo|runas|terminal|스크립트/i.test(text);
}

function hasExecutionVerb(text) {
  return /실행|수행|호출|구동|execute|executed|executes|run\b|ran\b|invoke|invoked|launch(?:ed)?|start(?:ed)?|issued|performed/i.test(text);
}

function hasFailureCue(text, status) {
  const combined = text + " " + status;
  const cue = /실패|오류|거부|취소|중단|차단(?:됨|되었|됐다)?|실행되지|실행 불가|추가되지|부여되지|권한을 얻지 못|failed|failure|error|denied|cancelled|canceled|aborted|blocked|not executed|did not execute|never ran|failed to execute|failed to add|grant failed|unsuccessful/i.test(combined);
  const negated = /(?:실패|오류|거부|취소|중단)\s*(?:가|는|은|도)?\s*(?:없|아니|않)|(?:실패|오류|거부)\s*하지 않았|no (?:failures?|errors?|denials?|cancellations?)|without (?:failure|error|denial)|not failed/i.test(combined);
  const structuredFailure = /^(?:false|failed?|failure|error|denied|cancelled|canceled|aborted|blocked|unsuccessful)$/.test(status.trim());
  const structuredSuccess = /^(?:true|success|succeeded|successful|ok|passed)$/.test(status.trim());
  return structuredFailure || (cue && !negated && !structuredSuccess);
}

function hasAttemptCue(text) {
  return /시도|시도만|요청만|하려고|attempt(?:ed|ing)?|tried to|trying to|try to|attempt only/i.test(text);
}

function hasExplicitNonExecution(text) {
  if (!hasCommandMention(text)) return false;
  // A separate "no privilege change" statement must not be mistaken for "no command executed".
  return /명령.{0,14}(?:미실행|실행.{0,4}(?:하지 않|못|되지 않|안)|취소|거부|실패|없(?:었습니다|습니다|음|다)?)|(?:미실행|실행 불가|실행되지|실행 안|실행하지 않|실행 못|취소|거부|실패).{0,14}(?:명령|command)|command.{0,24}(?:not run|not executed|never ran|was not executed|cancelled|canceled|denied|failed)|(?:no|without)\\s+(?:an?\\s+)?(?:admin(?:istrator)?\\s+|privileged\\s+|elevated\\s+)?command/i.test(text);

function hasAdminCommand(alert, text = descriptionOf(alert)) {
  const commandPresent = hasCommandMention(text)
    || Boolean(oneLine(alert?.data?.command ?? alert?.data?.command_line));
  if (!commandPresent) return false;
  const explicitPrivilegedCommand = /(?:관리자|권한|privileged|elevated|administrator|admin).{0,22}(?:명령|command|shell|powershell|스크립트)|(?:명령|command).{0,22}(?:관리자|권한|privileged|elevated|administrator|admin)/i.test(text);
  const privilegeContext = isAdminGroup(alert, text)
    || /관리자|administrator|admin\b|privileg|elevat|sudo|runas|wheel|superuser/i.test(text);
  const failureNearCommand = /(?:명령|command|shell).{0,36}(?:실패|오류|거부|취소|failed|error|denied|cancelled|canceled)|(?:실패|오류|거부|취소|failed|error|denied|cancelled|canceled).{0,36}(?:명령|command|shell)/i.test(text);
  return (hasExecutionVerb(text) || failureNearCommand)
    && (explicitPrivilegedCommand || privilegeContext);
}

function hasElevationActivity(text) {
  return /권한\s*상승|권한\s*승격|권한\s*변경|권한\s*부여|관리자가\s*(?:된|되었|됐|되는)|관리자로\s*(?:승격|바뀌|되었|됐)|관리자\s*권한.{0,28}(?:바뀌|변경|전환|승격|얻|부여|증가)|(?:세션|계정).{0,32}(?:관리자|admin|elevated|privileged).{0,24}(?:권한|privilege|role)|privilege escalation|privilege elevation|privilege change|elevat(?:ed|ion).{0,32}(?:admin|administrator|privilege|session)|(?:admin|administrator) privileges?.{0,28}(?:changed|granted|elevated|increased)|became an? admin|gained (?:admin|administrator|elevated) privileges|granted (?:admin|administrator) privileges/i.test(text);
}

function hasSuccessfulElevation(text) {
  return hasElevationActivity(text)
    && /성공|완료|획득|얻|부여받|승격|관리자가\s*(?:된|되었|됐|되는)|관리자로\s*(?:승격|바뀌|되었|됐)|gained|granted|successfully|became an? admin|elevated to|privilege escalation succeeded/i.test(text);
}

function hasSessionElevation(text) {
  const session = /세션|session/i.test(text);
  const privilege = /관리자\s*권한|권한\s*상승|elevat|privileg|administrator|admin/i.test(text);
  const changed = /바뀌|변경|전환|승격|부여|얻|became|changed|switched|elevated|granted|converted|promoted/i.test(text);
  return session && privilege && changed;
}

function isOffHours(text) {
  return /(?:업무|근무|수업).{0,24}(?:시간|시각).{0,12}(?:밖|외|벗어나|지나)|(?:업무|근무|수업).{0,24}(?:아니|않|외|밖).{0,20}(?:시각|시간|때)|야간|심야|off.?hours|after hours|outside.{0,24}(?:hours|class|work)|during the night|at night/i.test(text);
}

function isUnfamiliarAddress(text) {
  const unfamiliar = /처음|낯선|미확인|새로운|미관측|unknown|unfamiliar|unrecognized|previously unseen|first[ -]?seen|newly observed/i.test(text);
  const address = /주소|ip\b|출발지|원격|source|address|origin|request/i.test(text);
  return unfamiliar && address;
}

function hasValidSourceIp(alert) {
  const parts = oneLine(alert?.data?.srcip).split(".");
  return parts.length === 4
    && parts.every((part) => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function hasTrustedAccountId(alert) {
  const identity = alert?.identity;
  const subjectId = oneLine(identity?.subjectId);
  return identity?.source === "trusted-directory"
    && /^[A-Za-z0-9._:-]{1,128}$/.test(subjectId);
}

function hasRequiredBlockEvidence(alert) {
  const ruleLevel = Number(alert?.rule?.level);
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  return Number.isFinite(ruleLevel)
    && ruleLevel >= PATTERN_SPEC.thresholds.blockMinimumRuleLevel
    && hasValidSourceIp(alert)
    && mitre.some((id) => id === "T1078" || id === "T1068")
    && hasTrustedAccountId(alert);
}

function hasOtherAccountCommand(text, adminCommand) {
  return adminCommand && /다른 계정|타 계정|another account|different account|on behalf of|using another account/i.test(text);
}

function isRoutineContext(text) {
  const positive = /평소|정상|승인된|허용된|예상된|일상|(?:^|[^a-z])(?:routine|usual|regular|known|trusted|approved|authorized|expected|legitimate|normal)(?:[^a-z]|$)/i.test(text);
  const negated = /비정상|정상이 아니|정상적이지 않|정상.{0,10}(?:아니|않|어렵)|승인되지 않|허용되지 않|예상되지 않|평소.{0,10}(?:아니|않)|(?:not|never|isn't|is not|untrusted|unauthorized|unexpected|illegitimate|abnormal)\b/i.test(text);
  return positive && !negated;
}

function isRoutineOperation(text) {
  return /로그인|로그아웃|sign(?:ed)?\s*in|sign(?:ed)?\s*out|log(?:ged)?\s*in|log(?:ged)?\s*out|비밀번호|password change|읽기만|읽기 전용|read.only|목록.{0,12}(?:조회|열람)|조회|열람|자기.{0,12}(?:계정|세션)|own (?:account|session)|자료실|예약 작업|scheduled task|task check|열었습니다|opened|viewed|listed|queried|looked up/i.test(text);
}

function hasExplicitReadOnlyEvidence(text) {
  return /읽기만|읽기 전용|read.only|목록.{0,12}(?:조회|열람)|조회|열람|listed|queried|looked up/i.test(text);
}

function hasExplicitNoChangeEvidence(text) {
  return /변경.{0,12}(?:없|없었|없습니다|없음|되지 않)|변경은 없|변경하지 않았|no changes|unchanged|without modification/i.test(text);
}

// 정상 기록은 명시적 정상 증거가 있을 때만 허용합니다.
// 이상 징후가 적혀 있지 않다는 사실만으로는 정상 증거가 되지 않습니다.
function normalEvidenceOf(text, alert, flags) {
  const explicitNoChange = hasExplicitNoChangeEvidence(text);
  const unconfirmedElevation = flags.elevation
    && !(explicitNoChange && !flags.successfulElevation);
  if (flags.groupAddition || flags.groupRemoval || unconfirmedElevation
      || flags.sessionElevation || flags.otherAccount || flags.unfamiliarAddress
      || flags.offHours || flags.failed || flags.attempted || flags.nonExecution) {
    return [];
  }

  const rawGroup = oneLine(alert?.data?.group ?? alert?.data?.target_group ?? alert?.group);
  const nonAdminGroup = isExplicitlyNonAdminGroup(text)
    || (Boolean(rawGroup) && !isAdminGroupName(rawGroup));

  if (nonAdminGroup && !flags.adminCommand) {
    return [isExplicitlyNonAdminGroup(text)
      ? "경보 설명에 대상이 관리자 그룹이 아니라고 명시됨"
      : "data.group이 관리자 그룹이 아닌 대상으로 확인됨"];
  }

  const evidence = [];
  const normalContext = isRoutineContext(text);
  const readOnly = hasExplicitReadOnlyEvidence(text);
  const noChange = hasExplicitNoChangeEvidence(text);

  if (normalContext) evidence.push("경보 설명에 평소·정상·승인된 활동 맥락이 명시됨");
  if (readOnly) evidence.push("읽기 전용 또는 조회 작업이 명시됨");
  if (noChange) evidence.push("권한·그룹 변경이 없었다고 명시됨");

  // 일반 로그인/로그아웃 등은 명시된 활동 유형 자체가 정상 근거가 될 수 있습니다.
  if (!flags.adminCommand && !hasCommandMention(text) && isRoutineOperation(text)) {
    evidence.push("로그인·로그아웃·일반 계정 조회 등 일상 작업 유형이 명시됨");
  }

  // 관리자 명령은 '낯선 주소가 아니다'라는 이유만으로 정상 처리하지 않습니다.
  // 평소/승인 맥락 또는 명시적인 읽기 전용·조회 근거가 있어야 합니다.
  if (flags.adminCommand && !normalContext && !readOnly && !noChange) return [];
  return [...new Set(evidence)];
}

function describeDecisionEvidence(alert, flags, normalEvidence = []) {
  const evidence = [...normalEvidence];
  if (flags.successfulElevation) evidence.push("성공한 권한 상승 표현 확인");
  else if (flags.elevation || flags.sessionElevation) evidence.push("권한 상승·변경 표현 확인");
  if (flags.groupAddition) evidence.push("관리자 그룹 추가 표현 확인");
  if (flags.groupRemoval) evidence.push("관리자 그룹 제거 표현 확인");
  if (flags.adminCommand) evidence.push("관리자 명령 실행 또는 실행 실패 표현 확인");
  if (flags.failed) evidence.push("실패·오류·거부·취소 신호 확인");
  if (flags.attempted) evidence.push("시도-only 표현 확인");
  if (flags.nonExecution) evidence.push("명령 미실행 표현 확인");
  if (flags.otherAccount) evidence.push("다른 계정 권한 사용 표현 확인");
  if (flags.unfamiliarAddress) evidence.push("낯선 주소 표현 확인");
  if (flags.offHours) evidence.push("업무·수업 시간 외 표현 확인");

  const privilegeSignal = flags.groupAddition || flags.groupRemoval
    || flags.adminCommand || flags.elevation || flags.sessionElevation;
  if (privilegeSignal) {
    const ruleLevel = Number(alert?.rule?.level);
    evidence.push(Number.isFinite(ruleLevel)
      ? (ruleLevel >= PATTERN_SPEC.thresholds.blockMinimumRuleLevel ? `rule.level ${PATTERN_SPEC.thresholds.blockMinimumRuleLevel} 이상 확인` : "rule.level 10 미만이므로 차단 기준 미충족")
      : "rule.level이 없거나 유효하지 않음");
    evidence.push(hasValidSourceIp(alert)
      ? "data.srcip이 유효한 IPv4 주소임"
      : "data.srcip이 없거나 유효한 IPv4 주소가 아님");
    const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
    evidence.push(mitre.some((id) => id === "T1078" || id === "T1068")
      ? "rule.mitre에 T1068 또는 T1078이 있음"
      : "rule.mitre에 T1068/T1078이 없음");
    evidence.push(hasTrustedAccountId(alert)
      ? "identity.source가 trusted-directory이고 subjectId 형식이 유효함"
      : "trusted-directory 출처 또는 유효한 subjectId가 확인되지 않음");
  }

  return evidence.length
    ? evidence.join("; ")
    : "분류를 뒷받침하는 구체적인 정상 또는 공격 근거가 확인되지 않음";
}
function patternById(id) {
  return PATTERN_SPEC.patterns.find((pattern) => pattern.id === id)
    ?? PATTERN_SPEC.patterns[PATTERN_SPEC.patterns.length - 1];
}

function output(patternId, confidence, evidenceNote) {
  const pattern = patternById(patternId);
  const action = confidence >= PATTERN_SPEC.thresholds.blockMinimumConfidence
    ? "block"
    : confidence >= PATTERN_SPEC.thresholds.alertMinimumConfidence
      ? "alert"
      : "record";
  const label = pattern.id + ": " + pattern.name;
  const details = oneLine(evidenceNote);
  return {
    action,
    confidence,
    reason: details
      ? oneLine(label + " — 확인 근거: " + details)
      : oneLine(label + " — " + pattern.evidence)
  };
}

// 단일 경보 안의 설명·구조화 필드·결과 상태를 함께 평가합니다.
// rule.level이나 MITRE 태그만으로 공격을 단정하지 않고, 다른 경보와도 상관분석하지 않습니다.
export function decide(alert) {
  const text = descriptionOf(alert);
  const status = statusOf(alert);
  const isAdminGroupTarget = isAdminGroup(alert, text);
  const groupAddition = hasAdminGroupAddition(alert, text);
  const groupRemoval = hasAdminGroupRemoval(alert, text);
  const adminCommand = hasAdminCommand(alert, text);
  const elevation = hasElevationActivity(text);
  const successfulElevation = hasSuccessfulElevation(text);
  const sessionElevation = hasSessionElevation(text);
  const offHours = isOffHours(text);
  const unfamiliarAddress = isUnfamiliarAddress(text);
  const otherAccount = hasOtherAccountCommand(text, adminCommand);
  const attempted = hasAttemptCue(text);
  const failed = hasFailureCue(text, status);
  const nonExecution = hasExplicitNonExecution(text);
  const commandSuccessful = adminCommand && !nonExecution && !failed && !attempted;
  const groupCycle = isAdminGroupTarget && groupAddition && groupRemoval;
  const count = Number(alert?.data?.count);
  const bulkGroupAddition = isAdminGroupName(oneLine(alert?.data?.group))
    && groupAddition && Number.isFinite(count) && count >= 3;
  const flags = {
    groupAddition, groupRemoval, adminCommand, elevation, successfulElevation,
    sessionElevation, failed, attempted, nonExecution, otherAccount,
    unfamiliarAddress, offHours
  };
  const normalEvidence = normalEvidenceOf(text, alert, flags);
  const observedEvidence = describeDecisionEvidence(alert, flags, normalEvidence);
  const classify = (patternId, confidence, note = "") =>
    output(patternId, confidence, [note, observedEvidence].filter(Boolean).join(" "));

  // record는 경보 안에서 확인된 정상 근거가 있을 때만 반환합니다.
  if (normalEvidence.length > 0) {
    return classify(
      "ordinary_account_activity",
      0.10,
      "명시적인 정상 활동 근거가 확인되어 record로 분류함."
    );
  }

  const privilegeRelevant = isAdminGroupTarget || groupAddition || groupRemoval
    || adminCommand || elevation || sessionElevation
    || /관리자\s*권한|권한\s*상승|권한\s*변경|privilege escalation|privilege change|administrator privileges/i.test(text);

  // 실패·취소·미실행·시도-only는 공격 성공으로 간주하지 않습니다.
  if (privilegeRelevant && (failed || attempted || nonExecution)) {
    return classify("ambiguous_privilege_activity", 0.68);
  }

  // patterns.json의 강한 단일 경보 패턴만 차단 후보로 삼고, 모든 필수 증거를 차단 직전에 확인합니다.
  if (!groupCycle && commandSuccessful && (successfulElevation || groupAddition)) {
    const patternId = successfulElevation ? "recent_elevation_then_admin_command" : "admin_group_added_then_admin_command";
    if (!hasRequiredBlockEvidence(alert)) {
      return classify(patternId, 0.68, "강한 공격 행동은 보이지만 rule.level, 유효 IP, MITRE, 신뢰 계정 증거가 모두 충족되지 않아 차단하지 않습니다.");
    }
    return classify(patternId, 0.96);
  }

  // 업무 외 시간·낯선 주소·명령 조합만으로는 patterns.json의 block 조건이 아니므로 여기서 차단하지 않습니다.
  // 해당 경보는 아래의 off-hours/unfamiliar 패턴에서 alert로 분류됩니다.

  // 대량 관리자 그룹 추가는 data.group과 data.count 조건 및 모든 필수 증거를 같은 경보에서 확인합니다.
  if (!groupCycle && bulkGroupAddition && !failed && !attempted && !nonExecution) {
    if (!hasRequiredBlockEvidence(alert)) {
      return classify("bulk_admin_group_addition", 0.68, "대량 관리자 그룹 추가 신호는 있으나 필수 차단 증거가 부족해 차단하지 않습니다.");
    }
    return classify("bulk_admin_group_addition", 0.90);
  }

  // 제거 후 재추가가 포함된 순환·불명확한 변경은 한 번의 성공적 추가로 간주하지 않습니다.
  if (groupCycle) return classify("ambiguous_privilege_activity", 0.68);

  // 단독 관리자 그룹 추가는 위험 신호이지만 다른 강한 신호가 없으므로 alert로 남깁니다.
  if (groupAddition && !groupRemoval) return classify("admin_group_addition", 0.68);
  if (groupRemoval) return classify("ambiguous_privilege_activity", 0.68);

  // 낯선 주소 또는 다른 계정의 관리자 명령은 단독으로 차단하지 않고 alert로 남깁니다.
  if (otherAccount || (adminCommand && unfamiliarAddress)) {
    return classify("unfamiliar_admin_command", 0.68);
  }
  if (offHours && (adminCommand || isAdminGroupTarget || elevation || sessionElevation)) {
    return classify("off_hours_privilege_use", 0.72);
  }
  if (sessionElevation || elevation) return classify("ambiguous_privilege_activity", 0.68);

  // 낯선 주소·업무 외 시간 신호가 없더라도 정상 활동 근거가 없으면 record로 낮추지 않습니다.
  if (adminCommand && !otherAccount && !unfamiliarAddress && !offHours) {
    return classify(
      "ambiguous_privilege_activity",
      0.68,
      "정상 사용을 뒷받침하는 명시적 근거가 없어 alert로 분류함. 이상 징후가 명시되지 않았다는 사실만으로 정상이라고 판단하지 않음."
    );
  }

  // 정상 근거가 없고 확정 공격 패턴도 충족하지 않은 미분류 경보는 조사 알림으로 남깁니다.
  return classify(
    "ambiguous_privilege_activity",
    0.68,
    "명시적 정상 근거와 확정 공격 패턴이 모두 충분하지 않아 record가 아닌 alert로 분류함."
  );
}
