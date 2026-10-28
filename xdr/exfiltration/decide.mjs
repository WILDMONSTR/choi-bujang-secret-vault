// 독립 심판용 판정기: import, 네트워크 요청, 파일 입출력을 사용하지 않습니다.
// 아래 상수는 patterns.json의 판단 패턴과 임계값을 그대로 내장한 것입니다.
const PATTERN_SPEC = Object.freeze({
  "schema": "aleph.xdr.patterns.v1",
  "moduleKey": "exfiltration",
  "attackTechniques": [
    {
      "id": "T1041",
      "name": "Exfiltration Over C2 Channel",
      "source": "https://attack.mitre.org/techniques/T1041/"
    },
    {
      "id": "T1048",
      "name": "Exfiltration Over Alternative Protocol",
      "source": "https://attack.mitre.org/techniques/T1048/"
    }
  ],
  "patterns": [
    {
      "id": "new_destination_bulk_transfer",
      "name": "미관측 목적지로 대량 자료 반출",
      "techniqueIds": [
        "T1041",
        "T1048"
      ],
      "condition": "처음 보는 목적지로 실제 외부 자료가 50 MB 이상 전송됐고 규칙 수준 10 이상·유효 출발지와 목적지가 확인됨",
      "confidence": 0.94,
      "evidence": "T1048/T1041 관련 경보에서 새 목적지와 큰 외부 전송량이 동일 사건에 확인됨"
    },
    {
      "id": "off_hours_archive_export",
      "name": "업무 외 시간의 대용량 압축 파일 반출",
      "techniqueIds": [
        "T1048"
      ],
      "condition": "업무·수업 시간 밖에 압축 파일이 실제로 50 MB 이상 외부 반출됐고 수준 10 이상·유효 출발지와 목적지가 확인됨",
      "confidence": 0.96,
      "evidence": "T1048의 대체 전송 경로와 업무 외 시각의 압축 파일 반출이 함께 탐지됨"
    },
    {
      "id": "repeated_large_export",
      "name": "동일 목적지로 대용량 반복 전송",
      "techniqueIds": [
        "T1041",
        "T1048"
      ],
      "condition": "같은 목적지로 5회 이상 반복된 총 50 MB 이상의 외부 전송과 수준 10 이상·유효 주소가 확인됨",
      "confidence": 0.92,
      "evidence": "T1041/T1048 관련 경보에 외부 목적지로 큰 양이 여러 차례 이동한 정황이 기록됨"
    },
    {
      "id": "unusual_port_bulk_export",
      "name": "비정상 포트로 대량 자료 전송",
      "techniqueIds": [
        "T1048"
      ],
      "condition": "평소와 다른 포트를 통해 실제 자료가 50 MB 이상 전송됐고 수준 10 이상·유효 주소·T1048 근거가 확인됨",
      "confidence": 0.9,
      "evidence": "T1048의 비정상 전송 프로토콜·포트 사용과 높은 전송량이 같은 경보에 확인됨"
    },
    {
      "id": "unfamiliar_archive_export",
      "name": "새 목적지로 연속 압축 파일 반출",
      "techniqueIds": [
        "T1048"
      ],
      "condition": "압축 파일이 처음 보는 목적지로 50 MB 이상 연속 또는 복수 전송됐고 수준 10 이상·유효 주소가 확인됨",
      "confidence": 0.94,
      "evidence": "T1048의 새로운 외부 주소와 압축 자료의 연속·묶음 전송이 함께 관측됨"
    },
    {
      "id": "rapid_full_repository_copy",
      "name": "짧은 시간에 자료실 전체 복사",
      "techniqueIds": [
        "T1041",
        "T1048"
      ],
      "condition": "짧은 시간에 자료실 전체가 외부 주소로 50 MB 이상 복사됐고 수준 10 이상·유효 주소가 확인됨",
      "confidence": 0.97,
      "evidence": "T1041/T1048 관련 경보에서 단일 대량 전송으로 전체 자료가 외부로 복사됨"
    },
    {
      "id": "command_channel_bulk_export",
      "name": "명령 통로를 통한 대용량 반복 유출",
      "techniqueIds": [
        "T1041"
      ],
      "condition": "명령 통로에서 큰 자료가 외부로 반복 전송되고 50 MB 이상·수준 10 이상·유효 주소가 확인됨",
      "confidence": 0.97,
      "evidence": "T1041의 명령·제어 통로를 통한 자료 반출과 반복 대량 송신이 함께 기록됨"
    },
    {
      "id": "multiple_destination_archive_export",
      "name": "여러 새 목적지로 동일 압축 파일 반출",
      "techniqueIds": [
        "T1048"
      ],
      "condition": "같은 압축 파일이 처음 보는 목적지 두 곳 이상으로 50 MB 이상 외부 전송됐고 수준 10 이상·유효 주소가 확인됨",
      "confidence": 0.96,
      "evidence": "T1048 관련 경보에 압축 자료를 여러 미관측 주소로 중복 반출한 흔적이 남음"
    },
    {
      "id": "suspicious_incomplete_export",
      "name": "근거 불충분한 자료 반출 징후",
      "techniqueIds": [
        "T1041",
        "T1048"
      ],
      "condition": "규칙 수준이 낮거나 전송 성공·목적지·양이 불명확해 차단하지 못하지만 비정상 목적지·실패·압축·전송량 이례 신호가 확인됨",
      "confidence": 0.68,
      "evidence": "T1041/T1048 경보에서 의심 정황이 있으나 악의적 외부 반출이 확정되지 않아 조사만 필요함"
    }
  ],
  "decisionThresholds": {
    "blockMinimumConfidence": 0.85,
    "alertMinimumConfidence": 0.5,
    "blockMinimumRuleLevel": 10,
    "bulkBytesMinimum": 50000000,
    "repeatedTransferMinimum": 5,
    "denyRuleTtlMinutes": 15
  }
});
const PATTERNS = Object.freeze(
  Object.fromEntries(PATTERN_SPEC.patterns.map((pattern) => [pattern.id, Object.freeze(pattern)]))
);

function clean(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return '';
  return String(value).replace(/[\r\n\t]+/g, ' ').trim().toLowerCase();
}

function validIPv4(raw) {
  const parts = clean(raw).split('.');
  return parts.length === 4 &&
    parts.every((part) => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function numberOf(value) {
  if (typeof value !== 'number' && typeof value !== 'string') return 0;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function determine(id, confidence, extra = '') {
  const pattern = PATTERNS[id];
  const action = confidence >= PATTERN_SPEC.decisionThresholds.blockMinimumConfidence
    ? 'block'
    : confidence >= PATTERN_SPEC.decisionThresholds.alertMinimumConfidence ? 'alert' : 'record';
  const reason = [pattern?.name ?? '정상 자료실 활동', extra].filter(Boolean).join(' — ');
  return { action, confidence, reason: reason.replace(/[\r\n\t]+/g, ' ') };
}

export function decide(alert) {
  const desc = clean(alert?.rule?.description);
  const data = alert?.data ?? {};
  const level = numberOf(alert?.rule?.level);
  const bytes = numberOf(data.bytes ?? data.total_bytes ?? data.size);
  const count = numberOf(data.count ?? data.transfers);
  const files = numberOf(data.files);
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const technique = (id) => mitre.includes(id);
  const sourceValid = validIPv4(data.srcip);
  const destinationValid = validIPv4(data.dstip);
  const unfamiliar = /처음\s*(?:보는|관측)|낯선|미확인|새로운\s*(?:주소|목적지)|평소(?:에)?\s*(?:와|과)?\s*다른\s*주소|first.seen|unfamiliar|unrecognized|unknown destination|new destination/i.test(desc);
  const compressed = /압축\s*파일|archive|zip(?:ped)?\s*file|compressed\s*file/i.test(desc);
  const offHours = /(?:업무|수업|근무)\s*시간\s*(?:밖|외)|업무\s*외|off.hours|after.hours/i.test(desc);
  const repeated = /연속|반복|(?:\d+)\s*번|same destination.*multiple|repeated/i.test(desc);
  const unusualPort = /평소에?\s*쓰지\s*않던\s*포트|비정상\s*포트|unusual port|non.standard port/i.test(desc);
  const commandChannel = /명령\s*통로|command.and.control|c2\s*channel|command\s*channel/i.test(desc);
  const wholeWorkspace = /자료실\s*전체|전체\s*(?:자료|파일)|entire\s*(?:workspace|repository)/i.test(desc);
  const multipleDestinations = /목적지\s*(?:두|2)\s*곳|여러\s*목적지|multiple\s*destinations?/i.test(desc);
  const outbound = /나갔|전송|반출|올라갔|외부|복사됐|송신|export|sent|uploaded|copied|transferred/i.test(desc);
  const noOutbound = /외부\s*전송은\s*아직\s*없|전송은\s*없|전송이?\s*실패|전송\s*실패|not\s*sent|no\s*external\s*transfer|failed\s*transfer/i.test(desc);
  const bulk = bytes >= PATTERN_SPEC.decisionThresholds.bulkBytesMinimum;
  const enoughRepetitions = count >= PATTERN_SPEC.decisionThresholds.repeatedTransferMinimum;
  const highConfidencePrerequisites = level >= PATTERN_SPEC.decisionThresholds.blockMinimumRuleLevel
    && bulk && sourceValid && destinationValid && outbound && !noOutbound
    && (technique('T1041') || technique('T1048'));
  const benignAction = /읽었|읽기|공지를?\s*읽|검색\s*결과|새로고침|내\s*메모를?\s*저장|수업\s*자료\s*주소로\s*작은\s*동기화|첨부\s*그림|세션\s*확인|로그아웃|viewed|logged\s*out|refresh|synchroniz/i.test(desc);

  // 입증된 대량 외부 전송만 차단 후보입니다. 사용자명이나 경보 ID는 판정 조건이 아닙니다.
  if (highConfidencePrerequisites) {
    if (technique('T1048') && compressed && multipleDestinations && unfamiliar) {
      return determine('multiple_destination_archive_export', 0.96);
    }
    if (technique('T1041') && commandChannel && repeated) {
      return determine('command_channel_bulk_export', 0.97);
    }
    if (wholeWorkspace && /짧은\s*시간|rapid|quick/i.test(desc)) {
      return determine('rapid_full_repository_copy', 0.97);
    }
    if (technique('T1048') && compressed && offHours) {
      return determine('off_hours_archive_export', 0.96);
    }
    if (technique('T1048') && compressed && unfamiliar && (repeated || files >= 2)) {
      return determine('unfamiliar_archive_export', 0.94);
    }
    if (technique('T1048') && unusualPort) {
      return determine('unusual_port_bulk_export', 0.90);
    }
    if (repeated && (enoughRepetitions || /\d+\s*번\s*반복|반복됐/.test(desc))) {
      return determine('repeated_large_export', 0.92);
    }
    if (unfamiliar) {
      return determine('new_destination_bulk_transfer', 0.94);
    }
  }

  // 정상 읽기·저장·동기화는 기술 태그만으로 공격으로 승격하지 않습니다.
  // 증거가 불충분한 이벤트는 차단하지 않고 알림으로 넘깁니다.
  if (level <= 3 && benignAction && bytes < 100000 && !unfamiliar && !offHours
      && !compressed && !unusualPort && !commandChannel && !wholeWorkspace) {
    return determine('ordinary_account_activity', 0.10, '일상 자료실 작업');
  }
  const suspicious = unfamiliar || offHours || compressed || repeated || unusualPort
    || commandChannel || wholeWorkspace || multipleDestinations
    || /전송량|반출|대용량|backup|백업|전송|평소보다|부분만|일부만|실패|파일\s*수가?\s*(?:한\s*번\s*)?늘|파일\s*수\s*증가/i.test(desc)
    || (outbound && (technique('T1041') || technique('T1048')) && bytes >= 1000000);
  if (suspicious) {
    return determine('suspicious_incomplete_export', 0.68, '반출 성공·위험도 또는 복합 증거가 부족하여 조사');
  }
  return determine('ordinary_account_activity', 0.10, '유출 근거가 없는 일반 활동');
}
