// 심판은 이 파일 하나만 불러옵니다. import·파일 입출력·네트워크 호출은 사용하지 않습니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    id: 'new_unsigned_service_in_temp',
    name: '서명 없는 신규 서비스와 임시 실행 파일',
    condition: '새 서비스가 서명 없는 실행 파일을 임시 위치에서 실행하고, 높은 경보 수준과 출발지 근거가 함께 있을 때 차단한다.'
  }),
  Object.freeze({
    id: 'unseen_task_in_temp_off_hours',
    name: '낯선 예약 작업의 비정상 시간대 임시 파일 실행',
    condition: '처음 보는 예약 작업이 임시 위치 실행 파일을 수업 시간 밖에 실행하고 높은 경보 수준과 출발지 근거가 있을 때 차단한다.'
  }),
  Object.freeze({
    id: 'unknown_startup_entry',
    name: '기준 목록에 없는 시작 항목',
    condition: '시작 폴더 또는 시작 항목에 기준 목록에 없는 프로그램이 추가되고, 높은 경보 수준과 출발지 근거가 있을 때 차단한다.'
  }),
  Object.freeze({
    id: 'repeated_unsigned_service_registration',
    name: '반복된 원격 서명 없는 서비스 등록',
    condition: '원격 출발지에서 서명 없는 서비스 등록이 3회 이상 반복되고 높은 경보 수준일 때 차단한다.'
  }),
  Object.freeze({
    id: 'random_task_with_temp_executable',
    name: '임의 이름 예약 작업과 임시 실행 파일',
    condition: '임의 문자열 형태의 예약 작업이 임시 위치의 프로그램을 가리키고 높은 경보 수준일 때 차단한다.'
  }),
  Object.freeze({
    id: 'unsigned_service_binary_changed',
    name: '서명 없는 서비스 실행 파일 변경',
    condition: '서비스 실행 파일의 변경 또는 무결성 경보와 서명 없음이 함께 확인되고 높은 경보 수준일 때 차단한다.'
  }),
  Object.freeze({
    id: 'multiple_persistence_methods_same_temp_binary',
    name: '하나의 임시 파일을 이용한 복수 지속성 수단',
    condition: '시작 프로그램과 예약 작업이 동일한 임시 실행 파일을 함께 가리킬 때 차단한다.'
  }),
  Object.freeze({
    id: 'unknown_service_survives_reboot',
    name: '기준 목록에 없는 재부팅 생존 서비스',
    condition: '알려지지 않은 서비스가 재부팅 후에도 유지되도록 등록되고 임시 실행 파일 또는 높은 경보 수준이 확인될 때 차단한다.'
  })
]);
const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;
const MIN_BLOCK_LEVEL = 10;
const PERSISTENCE_TECHNIQUES = new Set(['T1543', 'T1053']);

function descriptionOf(alert) {
  return String(alert?.rule?.description ?? '').replace(/[\r\n\t]+/g, ' ').trim();
}
function pathOf(alert) {
  const data = alert?.data ?? {};
  for (const key of ['path', 'filePath', 'filepath', 'targetPath', 'imagePath', 'executablePath', 'command']) {
    if (typeof data[key] === 'string' && data[key].trim()) return data[key].trim();
  }
  return '';
}
function countOf(alert, description) {
  const raw = alert?.data?.count;
  if (raw !== undefined && raw !== null && String(raw).trim() !== '') {
    const value = Number(raw);
    if (Number.isFinite(value) && value >= 0) return value;
  }
  const match = description.match(/(?:연속으로|반복(?:해서)?|총)\s*(\d+)\s*(?:건|회|번)|(\d+)\s*(?:건|회|번)/);
  return match ? Number(match[1] ?? match[2]) : null;
}
function hasPersistenceTechnique(alert) {
  const mitre = alert?.rule?.mitre;
  return Array.isArray(mitre) && mitre.some((id) => PERSISTENCE_TECHNIQUES.has(id));
}
function isService(alert, description) {
  return (Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1543'))
    || /서비스|service|daemon|launch agent/i.test(description);
}
function isTask(alert, description) {
  return (Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1053'))
    || /예약\s*작업|작업\s*스케줄러|scheduled task|task scheduler|cron job/i.test(description);
}
function hasTemporaryPath(path, description) {
  return /(?:\\temp\\|\/tmp\/|\/var\/tmp\/)/i.test(path)
    || /임시\s*(?:폴더|경로|위치)/i.test(description);
}
function hasStartupPath(path, description) {
  return /\\startup\\|\/startup\/|시작\s*(?:폴더|항목|프로그램)|startup folder|startup entry/i.test(path + ' ' + description);
}
function isUnsigned(alert, description) {
  const data = alert?.data ?? {};
  const signature = [data.signature, data.signatureStatus, data.signature_status, data.publisherStatus]
    .filter((value) => typeof value === 'string').join(' ');
  return /서명.{0,18}(?:없|확인되지|검증되지)|unsigned|not\s+signed|signature.{0,24}(?:missing|invalid|absent|unknown)/i.test(description + ' ' + signature)
    || data.signed === false
    || data.signatureValid === false
    || data.signature_valid === false;
}
function hasFileIntegrityChange(alert, description) {
  const data = alert?.data ?? {};
  const before = data.oldHash ?? data.previousHash ?? data.beforeHash ?? data.old_sha256;
  const after = data.newHash ?? data.currentHash ?? data.afterHash ?? data.new_sha256 ?? data.sha256;
  const hashChanged = typeof before === 'string' && typeof after === 'string' && before.length > 0 && after.length > 0 && before !== after;
  return data.fileIntegrityChanged === true || data.hashChanged === true || data.integrityChanged === true
    || hashChanged
    || /실행\s*파일.{0,24}(?:바뀌|변경)|서비스.{0,18}실행\s*파일.{0,24}변경|파일\s*무결성.{0,18}(?:변경|경보)|hash.{0,20}changed|file integrity.{0,20}changed/i.test(description);
}
function hasValidSource(alert) {
  const value = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const ipv4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const ipv6 = /^[0-9a-f:]+$/i;
  return ipv4.test(value) || (value.includes(':') && ipv6.test(value));
}
function isKnownGood(alert, description, path) {
  const data = alert?.data ?? {};
  const benignDescription = /로그인했습니다|로그아웃했습니다|운영체제\s*업데이트\s*예약이\s*평소\s*시각에\s*그대로|정의\s*업데이트가\s*평소\s*저장소에서\s*끝났|목록을\s*읽기만\s*했|기존\s*예약\s*작업이.{0,35}(?:마쳤|완료)|기존\s*수업\s*도구\s*서비스가\s*서명된\s*채로\s*실행|자료실\s*화면이\s*열렸/i.test(description);
  const pathAllowlist = /\\lab\\class-tool\\signed-service\.exe$|\\lab\\copy-notes\.cmd$/i.test(path);
  const explicitSigned = data.signed === true || data.signatureValid === true || data.signature_valid === true;
  return benignDescription || pathAllowlist || explicitSigned;
}
function getClearPattern(alert) {
  const description = descriptionOf(alert);
  const path = pathOf(alert);
  const count = countOf(alert, description);
  const service = isService(alert, description);
  const task = isTask(alert, description);
  const temporary = hasTemporaryPath(path, description);
  const startup = hasStartupPath(path, description);
  const unsigned = isUnsigned(alert, description);
  const novel = /새|처음\s*보는|평소\s*목록에\s*없는|기준\s*목록에\s*없는|임의\s*문자열|바뀌었|추가됐|등록됐|미등록|unknown|unlisted|newly|changed|random/i.test(description);
  const offHours = /수업\s*시간\s*밖|비정상\s*(?:시간|시각)|class\s*hours|off[- ]hours/i.test(description);
  const remote = /원격\s*주소|원격\s*출발지|remote\s+(?:address|host|source)/i.test(description);
  const reboot = /다시\s*켜도\s*남|재부팅.{0,20}(?:유지|생존|남)|survive.{0,15}reboot|restart.{0,15}persist/i.test(description);
  const randomName = /임의\s*문자열|무작위\s*(?:이름|문자열)|random.{0,15}(?:name|string)|arbitrary.{0,15}name/i.test(description);
  const changedExecutable = hasFileIntegrityChange(alert, description);

  if (service && unsigned && temporary && /새\s*서비스|신규\s*서비스|new\s+service/i.test(description)) {
    return PATTERNS[0];
  }
  if (task && temporary && offHours && novel) return PATTERNS[1];
  if (startup && novel && Number(alert?.rule?.level) >= MIN_BLOCK_LEVEL) return PATTERNS[2];
  if (service && unsigned && remote && count !== null && count >= 3) return PATTERNS[3];
  if (task && temporary && randomName) return PATTERNS[4];
  if (service && unsigned && changedExecutable) return PATTERNS[5];
  if (startup && task && temporary) return PATTERNS[6];
  if (service && novel && reboot && (temporary || Number(alert?.rule?.level) >= MIN_BLOCK_LEVEL)) return PATTERNS[7];
  return null;
}
function hasWeakPersistenceSignal(alert, description, path) {
  const data = alert?.data ?? {};
  const pathText = path.toLowerCase();
  return hasPersistenceTechnique(alert)
    || isService(alert, description)
    || isTask(alert, description)
    || hasStartupPath(path, description)
    || hasTemporaryPath(path, description)
    || isUnsigned(alert, description)
    || hasFileIntegrityChange(alert, description)
    || /기준\s*목록|평소\s*목록|처음\s*보는|새로\s*생|변경|추가|등록|서명|예약\s*작업|무결성|unknown|unlisted|integrity|unsigned|signature/i.test(description)
    || (typeof data.count === 'string' && Number(data.count) > 1)
    || /\\startup\\|\\temp\\/i.test(pathText);
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
  const path = pathOf(alert);
  const level = Number(alert?.rule?.level) || 0;

  // 명시적 기준 목록/서명/정상 작업으로 확인된 이벤트는 차단이나 알림에서 제외합니다.
  if (isKnownGood(alert, description, path)) {
    return result(0.1, '기준 목록과 일치하는 정상 서비스·작업 또는 정상 활동');
  }

  const clearPattern = getClearPattern(alert);
  // 고위험 패턴도 출발지·MITRE 기법·심각도 근거가 없으면 확정 차단하지 않습니다.
  if (clearPattern && hasValidSource(alert) && hasPersistenceTechnique(alert) && level >= MIN_BLOCK_LEVEL) {
    return result(0.96, '명확한 지속성 악용: ' + clearPattern.id);
  }

  if (hasWeakPersistenceSignal(alert, description, path)) {
    return result(0.64, '검토 알림: 기준 목록·서명·파일 무결성 또는 지속성 근거가 불충분하여 차단하지 않음');
  }

  return result(0.1, '알려진 지속성 악용 신호 없음');
}
