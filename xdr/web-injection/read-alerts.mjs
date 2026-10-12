import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.resolve(HERE, '../fixtures/web-injection.json');

// 출력은 확인에 필요한 다섯 필드만 포함합니다. 자격 증명처럼 보이는 값은 먼저 가립니다.
const SECRET_PATTERNS = [
  /\bBearer\s+\S+/gi,
  /\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*[^\s,;]+/gi,
  /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(?:sk|pk|sb)_(?:live|test|publishable|secret)?_?[A-Za-z0-9_-]{20,}\b/gi,
  /\b[A-Za-z0-9_+/=-]{40,}\b/g,
];

function safeText(value) {
  if (value === null || value === undefined || value === '') return '(없음)';
  let text = String(value);
  for (const pattern of SECRET_PATTERNS) {
    text = text.replace(pattern, '[REDACTED]');
  }
  return text.replace(/[\r\n\t]+/g, ' ').trim();
}

function projectAlert(alert) {
  return {
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser ?? alert?.data?.user ?? alert?.data?.account),
    ruleLevel: safeText(alert?.rule?.level),
    description: safeText(alert?.rule?.description),
  };
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' ||
      fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('시험 경보 파일 형식이 올바르지 않습니다.');
  }

  const rows = fixture.alerts.map(projectAlert);
  for (const row of rows) {
    console.log(
      '시각: ' + row.timestamp +
      ' | 출발 주소: ' + row.sourceAddress +
      ' | 계정: ' + row.account +
      ' | 규칙 수준: ' + row.ruleLevel +
      ' | 설명: ' + row.description
    );
  }

  console.log('확인: 경보 ' + fixture.alerts.length + '건, 추출 줄 ' + rows.length + '줄');
  if (rows.length !== fixture.alerts.length) {
    throw new Error('경보 건수와 추출 줄 수가 일치하지 않습니다.');
  }
}

main().catch((error) => {
  console.error('경보 읽기 실패: ' + safeText(error?.message ?? '알 수 없는 오류'));
  process.exitCode = 1;
});
