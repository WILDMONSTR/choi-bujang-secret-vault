// 독립 심판용 순수 판정기입니다. import, 파일 입출력, 패키지 호출을 하지 않습니다.
const PATTERN_SPEC = Object.freeze({
  attackTechniques: Object.freeze([
    Object.freeze({ id: "T1068", name: "Exploitation for Privilege Escalation", source: "https://attack.mitre.org/techniques/T1068/" }),
    Object.freeze({ id: "T1078", name: "Valid Accounts", source: "https://attack.mitre.org/techniques/T1078/" })
  ]),
  // 0.85/0.5 are the rubric's action cutoffs. Per-pattern scores below are local heuristic values,
  // not numeric scores prescribed by MITRE ATT&CK; each score's operational rationale is recorded with its pattern.
  thresholds: Object.freeze({ blockMinimumConfidence: 0.85, alertMinimumConfidence: 0.5 }),
  patterns: Object.freeze([
    Object.freeze({
      id: "recent_elevation_then_admin_command",
      name: "권한 상승 직후 관리자 명령",
      condition: "같은 경보에서 성공한 권한 상승 직후 실제 관리자 명령이 실행되고 실패·취소·미실행 정황이 없으면 block한다. 별도 경보의 상관분석이나 부가 메타데이터는 필요하지 않다.",
      action: "confidence_threshold",
      confidence: 0.96,
      evidence: "T1068은 권한 상승 악용 기법이며, T1078은 유효 계정 악용의 맥락을 뒷받침한다.",
      confidenceRationale: "0.96은 같은 경보에 성공한 권한 상승과 실제 관리자 명령이 함께 나타나는 강한 결합 신호에 부여한 로컬 점수다.",
    }),
    Object.freeze({
      id: "admin_group_added_then_admin_command",
      name: "관리자 그룹 추가와 관리자 명령",
      condition: "같은 경보에서 성공한 관리자 그룹 추가와 실제 관리자 명령이 함께 있고 실패·취소·미실행 정황이 없으면 block한다. 별도 경보의 상관분석이나 부가 메타데이터는 필요하지 않다.",
      action: "confidence_threshold",
      confidence: 0.96,
      evidence: "T1078은 유효 계정의 악용을, T1068은 관리자 권한 상승 악용을 설명하는 MITRE ATT&CK 기법이다.",
      confidenceRationale: "0.96은 같은 경보에 성공한 관리자 그룹 추가와 실행된 관리자 명령이 함께 있는 경우에만 쓰는 로컬 점수다.",
    }),
    Object.freeze({
      id: "unfamiliar_admin_command",
      name: "낯선 주소 또는 다른 계정의 관리자 명령",
      condition: "낯선 출발지 또는 다른 계정의 권한으로 관리자 명령이 성공적으로 실행되면 block한다. 명령 실행 결과나 권한 관계가 불확실하면 alert로 남긴다.",
      action: "confidence_threshold",
      confidence: 0.90,
      evidence: "T1078은 정상 계정의 비정상적 사용이 계정 악용 가능성을 나타낼 수 있음을 설명한다.",
      confidenceRationale: "0.68은 의심 신호는 있으나 성공한 복합 공격이 확인되지 않은 경우의 로컬 alert 점수다.",
    }),
    Object.freeze({
      id: "off_hours_privilege_use",
      name: "업무 시간 밖 권한 사용",
      condition: "업무·수업 시간 밖에 관리자 권한 행위가 확인되고 실제 관리자 명령이 성공적으로 실행되면 block한다. 시간대만 확인되거나 실행 여부가 불분명하면 alert로 남긴다.",
      action: "confidence_threshold",
      confidence: 0.90,
      evidence: "T1078은 비정상적인 유효 계정 사용의 맥락을, T1068은 권한 상승 악용의 맥락을 뒷받침한다. ATT&CK은 이 조합의 숫자 확신도를 정하지 않으므로 0.96은 아래의 강한 3신호 조합에만 적용하는 로컬 점수다.",
      confidenceRationale: "0.72는 업무 외 시간과 구체적 권한 행위만 있는 경우의 alert 점수다. 업무 외 시간+처음 보는 주소+실제 관리자 명령이 모두 있으면 0.96으로 올린다.",
    }),
    Object.freeze({
      id: "bulk_admin_group_addition",
      name: "단일 경보의 대량 관리자 그룹 추가",
      condition: "같은 경보의 data.group이 관리자 그룹이고 data.count가 3 이상이며 실패·취소 정황이 없으면 대량 권한 변경 후보로 block한다. count 3은 이 저장소의 로컬 운영 기준이며 MITRE가 정한 임계값이 아니다. 원본 fixture의 pv-05는 count 4이고, 단일·2계정 추가는 이 분기로 차단하지 않는다.",
      action: "confidence_threshold",
      confidence: 0.90,
      evidence: "T1078은 유효 계정 악용 맥락만 뒷받침하며, 3계정 임계값은 외부 표준이 아니라 대량 변경과 단독 변경을 나누기 위한 명시적 로컬 휴리스틱이다. fixture pv-05의 count 4가 그 적용 예다.",
      confidenceRationale: "0.90은 동일 경보에 관리자 그룹 대상과 3개 이상 계정 변경 수가 함께 있고 실패·취소 신호가 없을 때 쓰는 로컬 점수다.",
    }),
    Object.freeze({
      id: "admin_group_addition",
      name: "단독 관리자 그룹 추가",
      condition: "관리자 그룹 추가가 성공적으로 확인되고 실패·취소·시도-only 정황이 없으면 block한다. 실패·취소·미확정 시도는 alert로 남긴다.",
      action: "confidence_threshold",
      confidence: 0.90,
      evidence: "관리자 그룹 구성원 변경이 실제로 발생했다는 구체적인 이벤트 증거를 사용한다. 실패 여부와 시도-only 신호를 먼저 확인한다.",
      confidenceRationale: "0.90은 관리자 그룹 추가가 확인됐고 실패·취소·시도 신호가 없을 때 사용하는 로컬 점수다.",
    }),
    Object.freeze({
      id: "ambiguous_privilege_activity",
      name: "결과가 불명확하거나 실패·취소된 권한 사용 시도",
      condition: "권한 상승 창 취소, 명령 없는 권한 상승, 실패한 관리자 명령, 낯선 세션 권한 변경처럼 조사 가치가 있지만 명확한 복합 공격으로 확정되지 않은 활동은 알림으로 분류한다.",
      action: "confidence_threshold",
      confidence: 0.68,
      evidence: "T1068은 권한 상승 악용과 관련되지만 실패·취소 또는 후속 명령이 없는 시도만으로 성공한 공격이라고 단정하지 않는다.",
      confidenceRationale: "0.68은 실패·취소·미실행 또는 결과가 불명확한 시도를 차단하지 않고 alert로 유지하기 위한 로컬 점수다.",
    }),
    Object.freeze({
      id: "ordinary_account_activity",
      name: "정상 계정·그룹 활동",
      condition: "로그인·로그아웃·읽기 전용 조회·비관리자 그룹 활동·평소 주소의 정상 관리자 사용처럼 권한 악용을 뒷받침하는 결합 신호가 없으면 기록만 한다.",
      action: "confidence_threshold",
      confidence: 0.1,
      evidence: "경보 설명이 변경 없음·읽기 전용·정상 주소 활동을 명시하고 T1068/T1078의 악용 신호가 결합되지 않으면 공격으로 올릴 근거가 없다.",
      confidenceRationale: "0.10은 명시적으로 정상·읽기 전용·변경 없음인 대조 이벤트에 쓰는 로컬 기록 점수다.",
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
  return /명령.{0,24}(?:없(?:습니다|음|다)?|않았|미실행|실행 불가|실행되지|실행 안|취소|거부|실패)|(?:미실행|실행 불가|실행되지|실행 안|취소|거부|실패).{0,24}(?:명령|command)|command.{0,24}(?:not run|not executed|never ran|was not executed|cancelled|canceled|denied|failed)|(?:no|without)\s+(?:an?\s+)?(?:admin(?:istrator)?\s+|privileged\s+|elevated\s+)?command/i.test(text);
}

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

function hasOtherAccountCommand(text, adminCommand) {
  return adminCommand && /다른 계정|타 계정|another account|different account|on behalf of|using another account/i.test(text);
}

function isRoutineContext(text) {
  return /평소|정상|승인된|허용된|예상된|일상|routine|usual|regular|known|trusted|approved|authorized|expected|legitimate|normal/i.test(text);
}

function isRoutineOperation(text) {
  return /로그인|로그아웃|sign(?:ed)?\s*in|sign(?:ed)?\s*out|log(?:ged)?\s*in|log(?:ged)?\s*out|비밀번호|password change|읽기만|읽기 전용|read.only|목록.{0,12}(?:조회|열람)|조회|열람|자기.{0,12}(?:계정|세션)|own (?:account|session)|자료실|예약 작업|scheduled task|task check|열었습니다|opened|viewed|listed|queried|looked up/i.test(text);
}

function isExplicitlyBenign(text, alert, flags) {
  if (isExplicitlyNonAdminGroup(text)
      && !flags.adminCommand && !flags.elevation && !flags.sessionElevation
      && !flags.failed && !flags.attempted) return true;

  const rawGroup = oneLine(alert?.data?.group ?? alert?.data?.target_group ?? alert?.group);
  const nonAdminGroup = Boolean(rawGroup) && !isAdminGroupName(rawGroup);
  if (nonAdminGroup
      && !flags.adminCommand && !flags.elevation && !flags.sessionElevation
      && !flags.failed && !flags.attempted) return true;

  // 정상 맥락은 위험한 권한 변경·다른 계정 사용·실패/시도가 함께 있으면 우선하지 않습니다.
  return (isRoutineContext(text) || isRoutineOperation(text))
    && !flags.groupAddition && !flags.groupRemoval
    && !flags.elevation && !flags.sessionElevation
    && !flags.otherAccount && !flags.unfamiliarAddress
    && !flags.offHours && !flags.failed && !flags.attempted;
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
  const bulkGroupAddition = groupAddition && Number.isFinite(count) && count >= 3;
  const flags = {
    groupAddition, groupRemoval, adminCommand, elevation, sessionElevation,
    failed, attempted, otherAccount, unfamiliarAddress, offHours
  };

  // 정상 대조 이벤트는 경보 수준이나 MITRE 태그만으로 알림/차단으로 올리지 않습니다.
  if (isExplicitlyBenign(text, alert, flags)) {
    return output("ordinary_account_activity", 0.10);
  }

  const privilegeRelevant = isAdminGroupTarget || groupAddition || groupRemoval
    || adminCommand || elevation || sessionElevation
    || /관리자\s*권한|권한\s*상승|권한\s*변경|privilege escalation|privilege change|administrator privileges/i.test(text);

  // 실패·취소·미실행·시도-only는 공격 성공으로 간주하지 않습니다.
  if (privilegeRelevant && (failed || attempted || nonExecution)) {
    return output("ambiguous_privilege_activity", 0.68);
  }

  // 한 경보에 성공한 권한 상승/그룹 추가와 실제 관리자 명령이 모두 있어야 차단합니다.
  if (!groupCycle && commandSuccessful && (successfulElevation || groupAddition)) {
    return output(successfulElevation ? "recent_elevation_then_admin_command" : "admin_group_added_then_admin_command", 0.96);
  }

  // 시간대 + 낯선 주소 + 실행된 관리자 명령은 독립적인 성공 복합 신호입니다.
  if (offHours && unfamiliarAddress && commandSuccessful) {
    return output("off_hours_privilege_use", 0.96);
  }

  // 단일 경보에서 계정 3개 이상이 관리자 그룹에 추가된 경우는 대량 변경으로 분류합니다.
  if (!groupCycle && bulkGroupAddition && !failed && !attempted) {
    return output("bulk_admin_group_addition", 0.90);
  }

  // 제거 후 재추가가 포함된 순환·불명확한 변경은 한 번의 성공적 추가로 간주하지 않습니다.
  if (groupCycle) return output("ambiguous_privilege_activity", 0.68);

  // 확인된 단독 관리자 그룹 추가도 명확한 권한 변경입니다. 실패·시도 신호는 위에서 alert로 분리됩니다.
  if (groupAddition && !groupRemoval) return output("admin_group_addition", 0.90);
  if (groupRemoval) return output("ambiguous_privilege_activity", 0.68);

  // 관리자 명령이 낯선 주소 또는 다른 계정의 권한으로 실제 실행됐다면 명확한 공격 신호입니다.
  if (adminCommand && commandSuccessful && (otherAccount || unfamiliarAddress)) {
    return output("unfamiliar_admin_command", 0.90);
  }

  // 업무·수업 시간 밖의 관리자 명령 실행은 단순 시간대 신호가 아니라 구체적인 권한 행위입니다.
  if (offHours && adminCommand && commandSuccessful) {
    return output("off_hours_privilege_use", 0.90);
  }

  // 명령의 성공 여부나 출발지·계정 맥락이 불확실한 의심 행위는 block 대신 alert입니다.
  if (otherAccount || (adminCommand && unfamiliarAddress)) {
    return output("unfamiliar_admin_command", 0.68);
  }
  if (offHours && (adminCommand || isAdminGroupTarget || elevation || sessionElevation)) {
    return output("off_hours_privilege_use", 0.72);
  }
  if (sessionElevation || elevation) return output("ambiguous_privilege_activity", 0.68);

  // 정상 주소에서 단독으로 실행된 일반 관리자 명령은 정상 대조 활동으로 기록합니다.
  if (adminCommand && !otherAccount && !unfamiliarAddress && !offHours) {
    return output("ordinary_account_activity", 0.10);
  }

  return output("ordinary_account_activity", 0.10);
}
