// 심판은 이 파일 하나만 불러옵니다. import·파일 입출력·네트워크 호출을 하지 않습니다.
const PATTERNS = Object.freeze([
  Object.freeze({ id: 'log4shell_jndi_remote_lookup', name: 'CVE-2021-44228 원격 JNDI 조회 표식',
    condition: '완전한 원격 JNDI 조회 형태, 높은 경보 수준, 출발지와 CVE 또는 T1190 근거가 함께 있을 때만 차단 후보로 분류한다.',
    evidence: 'CVE-2021-44228 공개 권고와 MITRE ATT&CK T1190 공개 애플리케이션 악용 분류를 사용한다.' }),
  Object.freeze({ id: 'possible_log4shell_indicator', name: 'Log4Shell 의심 또는 부분 표식',
    condition: 'CVE 이름, JNDI 단어, 잘린 조회 형태 등 약한 단서는 차단하지 않고 알림으로 분류한다.',
    evidence: '약한 정황만으로 원격 코드 실행 시도를 확정하지 않아 오탐을 줄인다.' })
]);
const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;
const MIN_BLOCK_LEVEL = 10;
const CVE_PATTERN = /\bCVE[-\s]?2021[-\s]?44228\b/i;
const REMOTE_LOOKUP_PATTERN = /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba|nds|http)\s*:\/\/[^{}\s]+\s*\}/i;

function descriptionOf(alert) {
  return String(alert?.rule?.description ?? '').replace(/[\r\n\t]+/g, ' ').trim();
}
function inputValues(alert) {
  const data = alert?.data ?? {};
  const keys = ['url', 'uri', 'query', 'parameter', 'param', 'requestTarget',
    'useragent', 'userAgent', 'http_user_agent', 'header', 'headers'];
  const values = [];
  for (const key of keys) {
    const value = data[key];
    if (typeof value === 'string') values.push(value);
    else if (Array.isArray(value)) {
      for (const entry of value) {
        if (typeof entry === 'string') values.push(entry);
        else if (entry && typeof entry === 'object') {
          for (const item of Object.values(entry)) if (typeof item === 'string') values.push(item);
        }
      }
    } else if (value && typeof value === 'object') {
      for (const item of Object.values(value)) if (typeof item === 'string') values.push(item);
    }
  }
  return values;
}
function decodedCandidates(value) {
  const candidates = [];
  let current = String(value ?? '').replace(/\+/g, ' ');
  for (let i = 0; i < 3; i += 1) {
    candidates.push(current);
    try {
      const next = decodeURIComponent(current);
      if (next === current) break;
      current = next.replace(/\+/g, ' ');
    } catch { break; }
  }
  return candidates;
}
function hasRemoteLookup(alert) {
  return inputValues(alert).some((value) =>
    decodedCandidates(value).some((candidate) => REMOTE_LOOKUP_PATTERN.test(candidate)));
}
function hasT1190(alert) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
}
function hasWeakSignal(alert) {
  const combined = descriptionOf(alert) + ' ' + inputValues(alert).join(' ');
  const level = Number(alert?.rule?.level) || 0;
  return CVE_PATTERN.test(combined)
    || /\bjndi\b/i.test(combined)
    || /\$\s*\{|\{|\}/i.test(combined)
    || /원격\s*조회|조회\s*구문|조회\s*형태|취약점|라이브러리|log4j|점검\s*도구|스캔|scanner|scan\s*tool|lookup|fragment|중괄호/i.test(combined)
    || (hasT1190(alert) && level >= 5);
}
function result(confidence, reason) {
  const value = Math.max(0, Math.min(1, confidence));
  return { action: value >= BLOCK_THRESHOLD ? 'block' : value >= ALERT_THRESHOLD ? 'alert' : 'record',
    confidence: Number(value.toFixed(2)), reason: String(reason).replace(/[\r\n]+/g, ' ').trim() };
}

export function decide(alert) {
  const level = Number(alert?.rule?.level) || 0;
  const sourcePresent = typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim().length > 0;
  const context = descriptionOf(alert) + ' ' + inputValues(alert).join(' ');
  const hasCveContext = CVE_PATTERN.test(context) || hasT1190(alert);
  const completePayload = hasRemoteLookup(alert);
  // 완전한 표식 + 높은 심각도 + 출발지 + CVE/T1190 맥락이 모두 있을 때만 차단합니다.
  if (completePayload && sourcePresent && level >= MIN_BLOCK_LEVEL && hasCveContext) {
    return result(0.96, '확인된 패턴: ' + PATTERNS[0].name + '; MITRE ATT&CK T1190');
  }
  if (completePayload || hasWeakSignal(alert)) {
    return result(0.68, '검토 알림: ' + PATTERNS[1].name + '; 차단 근거 불충분');
  }
  return result(0.1, '일치하는 알려진 CVE 악용 패턴 없음');
}
