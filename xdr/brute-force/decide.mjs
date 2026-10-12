// 심판은 이 파일만 불러옵니다. import, 파일 입출력, 네트워크 호출은 사용하지 않습니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    id: 'rapid_same_source_login_failures',
    name: '짧은 시간 내 동일 주소의 연속 로그인 실패',
    condition: '같은 출발지(srcip)에서 다수의 로그인 실패가 반복되며, 짧은 시간 집중 또는 큰 실패 횟수 등 강한 반복 추측 증거가 확인된다.',
    evidence: 'MITRE ATT&CK T1110은 반복적·체계적인 비밀번호 추측을 통한 계정 접근 시도를 무차별 대입으로 설명한다.'
  }),
  Object.freeze({
    id: 'same_password_multiple_accounts',
    name: '동일 주소에서 여러 계정에 같은 비밀번호 대입',
    condition: '같은 출발지(srcip)에서 여러 계정에 동일 비밀번호를 반복 대입하거나, 다수 계정의 로그인 실패가 같은 간격으로 반복되는 등 계정 분산 공격 증거가 뚜렷하다.',
    evidence: 'MITRE ATT&CK T1110.003은 하나 또는 소수의 공통 비밀번호를 여러 계정에 시도하는 Password Spraying을 설명한다.'
  })
]);
const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

function descriptionOf(alert) {
  return String(alert?.rule?.description ?? '');
}

function countOf(alert, description) {
  const raw = alert?.data?.count;
  if (raw !== undefined && raw !== null && String(raw).trim() !== '') {
    const value = Number(raw);
    if (Number.isFinite(value) && value >= 0) return value;
  }
  const match = description.match(/실패\s*(?:가|는)?\s*(\d+)\s*건|(\d+)\s*(?:login\s+)?failures?/i);
  return match ? Number(match[1] ?? match[2]) : null;
}

function minutesOf(description) {
  const ko = description.match(/(\d+)\s*분\s*(?:안(?:에)?|동안|이내|내에?)/);
  if (ko) return Number(ko[1]);
  const en = description.match(/(?:within|for|over|in)\s+(\d+)\s+minutes?/i);
  return en ? Number(en[1]) : null;
}

function loginFailure(description) {
  return /실패|login failed|login failure|authentication failed|failed login/i.test(description);
}

function successfulAfterFailure(description) {
  if (/성공(?:은|이)\s*없|no success|without successful login/i.test(description)) return false;
  return /실패[^.!?\n]{0,80}(?:(?:그\s*)?뒤(?:에)?|이후|후에)\s*(?:다시\s*)?(?:로그인\s*)?성공|성공했습니다|로그인이\s*성공|로그인에\s*성공|successful login|login succeeded/i.test(description);
}

function accountCount(alert, description) {
  const raw = alert?.data?.accounts;
  if (Array.isArray(raw)) return raw.filter(Boolean).length;
  if (typeof raw === 'string') {
    const entries = raw.split(/[,;|\s]+/).filter(Boolean);
    if (entries.length > 1) return entries.length;
  }
  const match = description.match(/계정\s*(\d+)\s*개|(?:multiple|different)\s+(\d+)\s+accounts?/i);
  if (match) return Number(match[1] ?? match[2]);
  const reversed = description.match(/(?:서로\s*다른\s*)?계정\s*(\d+)(?:개)?/);
  if (reversed) return Number(reversed[1]);
  return 0;
}

function multiAccounts(alert, description) {
  return accountCount(alert, description) > 1 ||
    /여러\s*계정|서로\s*다른\s*계정|계정\s*이름을\s*바꿔|다른\s*계정(?:들)?|두\s*계정|multiple\s+accounts|different\s+accounts/i.test(description);
}

function samePassword(description) {
  return /같은\s*비밀번호|동일한?\s*비밀번호|same\s+password|common\s+password/i.test(description);
}

function repeated(description) {
  return /연속|이어졌|이어집|반복|쌓였|쌓입|consecutive|repeated|sequential|같은\s*간격/i.test(description);
}

function attempted(description) {
  return /넣|대입|시도|attempt|tried|spray|실패|failure/i.test(description);
}

function result(confidence, reason) {
  const value = Math.max(0, Math.min(1, confidence));
  return {
    action: value >= BLOCK_THRESHOLD ? 'block' : value >= ALERT_THRESHOLD ? 'alert' : 'record',
    confidence: Number(value.toFixed(2)),
    reason: String(reason).replace(/[\r\n]+/g, ' ').trim()
  };
}

export function decide(alert) {
  const description = descriptionOf(alert);
  const ip = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const level = Number(alert?.rule?.level) || 0;
  const count = countOf(alert, description);
  const minutes = minutesOf(description);
  const failed = loginFailure(description);
  const success = successfulAfterFailure(description);
  const isMulti = multiAccounts(alert, description);
  const isSamePass = samePassword(description);
  const isRepeated = repeated(description);
  const isAttempted = attempted(description);
  const severityIsClear = level >= 10;

  // 차단은 출발지와 높은 심각도, 그리고 강한 공격 증거가 함께 있을 때만 허용합니다.
  // 시간 표기가 빠졌더라도 30건 이상의 명시적 로그인 실패는 강한 반복 추측 증거로 취급합니다.
  const clearFailureBurst = Boolean(ip) && severityIsClear && failed &&
    count !== null && count >= 30 && !success;

  // Password spraying은 실패라는 단어만 찾지 않고, 동일 비밀번호를 여러 계정에
  // 연속 대입했다는 표현도 공격 시도 증거로 인식합니다. 다수 계정의 반복 실패도 포함합니다.
  const clearSpray = Boolean(ip) && severityIsClear && isMulti && isRepeated &&
    isAttempted && ((isSamePass) || (failed && count !== null && count >= 15));

  if (clearFailureBurst) {
    let confidence = 0.86;
    if (count >= 60) confidence = minutes === 1 ? 0.98 : 0.96;
    else if (count >= 50) confidence = 0.96;
    else if (count >= 40) confidence = 0.92;
    return result(confidence, '패턴: ' + PATTERNS[0].name);
  }

  if (clearSpray) {
    const targets = accountCount(alert, description);
    const confidence = targets >= 15 ? 0.96 : targets >= 8 ? 0.92 : 0.88;
    return result(confidence, '패턴: ' + PATTERNS[1].name);
  }

  // 약한 증거·짧은 실패 묶음·성공 뒤의 실패는 차단하지 않고 알림으로만 분류합니다.
  const suspicious = failed || (isMulti && isSamePass && isAttempted) || (isMulti && isAttempted);
  if (suspicious && (level >= 5 || (count !== null && count >= 3))) {
    const name = isMulti || isSamePass ? PATTERNS[1].name : PATTERNS[0].name;
    return result(0.58, '패턴 일부 일치: ' + name + '; 애매한 시도는 차단하지 않고 알림 처리');
  }

  return result(0.1, '일치하는 공격 패턴 없음');
}
