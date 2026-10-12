// 심판은 이 파일만 불러옵니다. import, 파일 입출력, 네트워크 호출은 사용하지 않습니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    id: 'rapid_same_source_login_failures',
    name: '짧은 시간 내 동일 주소의 연속 로그인 실패',
    condition: '같은 출발지 주소(srcip)에서 짧은 시간 안에 로그인 실패 이벤트가 반복된다.',
    evidence: 'MITRE ATT&CK T1110은 반복적·체계적인 비밀번호 추측을 통한 계정 접근 시도를 무차별 대입으로 설명한다.'
  }),
  Object.freeze({
    id: 'same_password_multiple_accounts',
    name: '동일 주소에서 여러 계정에 같은 비밀번호 대입',
    condition: '같은 출발지 주소(srcip)에서 짧은 시간 동안 서로 다른 여러 계정에 같은 비밀번호를 대입한 로그인 실패 정황이 확인된다.',
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
function multiAccounts(alert, description) {
  const accounts = alert?.data?.accounts;
  if (Array.isArray(accounts) && accounts.length > 1) return true;
  if (typeof accounts === 'string' && accounts.split(/[,;|\s]+/).filter(Boolean).length > 1) return true;
  return /여러\s*계정|서로\s*다른\s*계정|계정\s*\d+\s*개|계정\s*이름을\s*바꿔|다른\s*계정(?:들)?|multiple\s+accounts|different\s+accounts/i.test(description);
}
function samePassword(description) {
  return /같은\s*비밀번호|동일한?\s*비밀번호|same\s+password|common\s+password/i.test(description);
}
function repeated(description) {
  return /연속|이어졌|이어집|반복|쌓였|쌓입|consecutive|repeated|sequential/i.test(description);
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
  const ip = alert?.data?.srcip;
  const level = Number(alert?.rule?.level) || 0;
  const count = countOf(alert, description);
  const minutes = minutesOf(description);
  const failed = loginFailure(description);
  const success = successfulAfterFailure(description);
  const isRepeated = repeated(description);
  const isMulti = multiAccounts(alert, description);
  const isSamePass = samePassword(description);
  const candidates = [];

  // 패턴 1은 실패 횟수와 짧은 시간 구간이 함께 뚜렷할수록 확신도를 높입니다.
  if (typeof ip === 'string' && ip.trim() && failed && count !== null && count >= 3 &&
      ((minutes !== null && minutes > 0 && minutes <= 5) || isRepeated)) {
    let confidence = 0.56;
    if (minutes !== null && minutes > 0 && minutes <= 5) {
      if (count >= 60 && minutes <= 1) confidence = 0.98;
      else if (count >= 50 && minutes <= 2) confidence = 0.96;
      else if (count >= 40 && minutes <= 3) confidence = 0.92;
      else if (count >= 30 && minutes <= 3) confidence = 0.86;
      else if (count >= 20) confidence = 0.75;
      else if (count >= 10) confidence = 0.65;
    } else if (count >= 60) confidence = 0.80;
    else if (count >= 40) confidence = 0.77;
    else if (count >= 20) confidence = 0.68;

    if (success) confidence = Math.min(confidence, 0.79);
    candidates.push({ confidence, reason: '패턴: ' + PATTERNS[0].name });
  }

  // 패턴 2는 여러 계정·같은 비밀번호가 필요합니다. 시간 근거 없이는 자동 차단하지 않습니다.
  if (typeof ip === 'string' && ip.trim() && failed && isMulti && isSamePass) {
    let confidence = isRepeated ? 0.78 : 0.68;
    if (minutes !== null && minutes > 0 && minutes <= 5) confidence = 0.96;
    if (success) confidence = Math.min(confidence, 0.79);
    candidates.push({ confidence, reason: '패턴: ' + PATTERNS[1].name });
  }

  if (candidates.length) {
    candidates.sort((a, b) => b.confidence - a.confidence);
    return result(candidates[0].confidence, candidates[0].reason);
  }

  // 여러 계정에 같은 비밀번호를 대입한 정황이지만 실패·시간 증거가 부족하면 알림만 남깁니다.
  if (typeof ip === 'string' && ip.trim() && isMulti && isSamePass &&
      /넣|대입|시도|attempt|tried|spray/i.test(description)) {
    return result(
      0.58,
      '패턴 일부 일치: ' + PATTERNS[1].name + '; 로그인 실패·시간 근거 추가 확인 필요'
    );
  }

  if (failed && (level >= 5 || (count !== null && count >= 3))) {
    const name = isMulti || isSamePass ? PATTERNS[1].name : PATTERNS[0].name;
    return result(0.58, '패턴 일부 일치: ' + name + '; 추가 확인 필요');
  }

  return result(0.1, '일치하는 공격 패턴 없음');
}
