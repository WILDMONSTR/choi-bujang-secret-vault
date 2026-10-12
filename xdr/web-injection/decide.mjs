// 심판은 이 파일 하나만 불러옵니다. 다른 파일·패키지·네트워크에 의존하지 않습니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    id: 'repeated_sql_syntax_in_parameter',
    name: '요청 인자 내 SQL 구문 반복',
    condition: '요청 인자에 SQL 연산·구문 결합 같은 구체적인 주입 표식이 있고, 같은 출발지에서 5회 이상 반복되며 경보 수준이 10 이상이다. select 같은 단어 하나만으로 판정하지 않는다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션의 취약점 악용을 다룬다. 요청 인자의 반복적인 SQL 구문 표식은 이 실습에서 탐지할 구체적인 웹 주입 신호다.'
  }),
  Object.freeze({
    id: 'repeated_script_tag_in_parameter',
    name: '요청 인자 내 스크립트 태그 주입 표식 반복',
    condition: '요청 인자에 스크립트 태그 또는 스크립트 삽입 표식이 구체적으로 나타나고, 같은 출발지에서 5회 이상 반복되며 경보 수준이 10 이상이다. 스크립트라는 일반 단어는 제외한다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션의 악용을 다룬다. 요청 인자에 반복되는 스크립트 태그 삽입 표식은 이 실습에서 탐지할 구체적인 웹 주입 신호다.'
  }),
  Object.freeze({
    id: 'repeated_path_traversal_parameter',
    name: '요청 인자 내 경로 거슬러 올라가기 표식 반복',
    condition: '요청 인자에 ../ 형태 또는 경로를 여러 단계 거슬러 올라가는 구체적인 표식이 있고, 같은 출발지에서 5회 이상 반복되며 경보 수준이 10 이상이다. up 같은 단어 하나는 제외한다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션의 취약점 악용을 다룬다. 요청 인자의 반복적인 ../ 경로 이탈 표식은 이 실습에서 탐지할 구체적인 웹 주입 신호다.'
  })
]);
const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;
const MIN_REPEATS = 5;
const MIN_BLOCK_LEVEL = 10;

function descriptionOf(alert) {
  return String(alert?.rule?.description ?? '');
}

function inputOf(alert) {
  const data = alert?.data ?? {};
  const values = [data.url, data.uri, data.query, data.parameter, data.param, data.requestTarget];
  return values.filter((value) => typeof value === 'string').join(' ');
}

function decoded(value) {
  let text = String(value ?? '').replace(/\+/g, ' ');
  try {
    text = decodeURIComponent(text);
  } catch {
    // Malformed percent-encoding remains text; the judge must stay deterministic.
  }
  return text;
}

function countOf(alert, description) {
  const raw = alert?.data?.count;
  if (raw !== undefined && raw !== null && String(raw).trim() !== '') {
    const value = Number(raw);
    if (Number.isFinite(value) && value >= 0) return value;
  }
  const match = description.match(/(\d+)\s*(?:번|회|건)/);
  return match ? Number(match[1]) : null;
}

function hasSqlSignal(description, input) {
  const declaredSignal =
    /SQL\s*(?:구문|표식)|데이터베이스\s*조회.{0,24}(?:이어\s*붙이|연결|표기)|SQL\s+syntax/i.test(description);
  // 구체적인 SQL 구조만 탐지합니다. select, sql, 따옴표 하나만으로는 공격으로 판정하지 않습니다.
  const sqlStructure =
    /\bunion\s+(?:all\s+)?select\b|\bselect\b[\s\S]{0,100}\bfrom\b|\b(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\b(?:or|and)\s+['"]?[a-z0-9_]+['"]?\s*=\s*['"]?[a-z0-9_]+['"]?|;\s*(?:select|insert|update|delete|drop)\b|\b(?:drop|truncate)\s+table\b|--(?:\s|$)/i.test(decoded(input));
  return declaredSignal || sqlStructure;
}

function hasScriptSignal(description, input) {
  return /스크립트\s*(?:삽입|태그|표식)|script\s*(?:injection|tag)|<\s*script\b|%3c\s*script|&lt;\s*script/i.test(description + ' ' + decoded(input));
}

function hasTraversalSignal(description, input) {
  return /경로.{0,24}(?:거슬러\s*올라가는\s*표기|이탈\s*표기)|(?:\.\.[/\\]){2,}|(?:%2e%2e(?:%2f|%5c)){2,}/i.test(description + ' ' + decoded(input));
}

function hasWeakInjectionClue(description) {
  return /따옴표.{0,30}(?:한\s*번|1번|반복은\s*없)|명령\s*구분자|이상한\s*검색|주입처럼\s*보이는|구분\s*문자.{0,20}(?:1건|한\s*건)|separator/i.test(description);
}

function hasValidLookingSource(alert) {
  return typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim().length > 0;
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
  const input = inputOf(alert);
  const level = Number(alert?.rule?.level) || 0;
  const count = countOf(alert, description);
  const sourcePresent = hasValidLookingSource(alert);
  const noRepetition = /반복은\s*없|반복되지\s*않|not\s+repeated|no\s+repetition/i.test(description);

  const signals = [];
  if (hasSqlSignal(description, input)) signals.push(PATTERNS[0]);
  if (hasScriptSignal(description, input)) signals.push(PATTERNS[1]);
  if (hasTraversalSignal(description, input)) signals.push(PATTERNS[2]);

  // 차단은 구체적인 지원 패턴, 반복 횟수, 경보 수준, 출발지 근거가 모두 있을 때만 합니다.
  if (signals.length > 0 && sourcePresent && level >= MIN_BLOCK_LEVEL &&
      count !== null && count >= MIN_REPEATS && !noRepetition) {
    const confidence = count >= 10 && signals.length > 1 ? 0.97 : count >= 10 ? 0.94 : 0.88;
    return result(confidence, '패턴: ' + signals.map((signal) => signal.name).join(' + '));
  }

  if (signals.length > 0) {
    return result(
      0.68,
      '패턴 일부 일치: ' + signals.map((signal) => signal.name).join(' + ') + '; 반복·위험 수준 근거 부족'
    );
  }

  // 범위 밖이거나 단발성인 의심 표식은 기록으로 묻지 않고 alert로만 올립니다.
  // 여기에는 명령 구분자나 단일 따옴표가 포함되지만, 새 차단 패턴으로 취급하지 않습니다.
  if (hasWeakInjectionClue(description) && level >= 5) {
    return result(
      0.58,
      '애매한 주입 정황: 지원 패턴 증거 불충분 (' + PATTERNS.map((pattern) => pattern.name).join(' / ') + ')'
    );
  }

  return result(0.1, '일치하는 웹 주입 패턴 없음');
}
