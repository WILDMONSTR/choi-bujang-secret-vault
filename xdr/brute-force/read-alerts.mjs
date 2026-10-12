import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, '../fixtures/brute-force.json');

// This is a read-only inspection helper. Keep it separate from decide.mjs.
const SECRET_PATTERNS = [
  /\bBearer\s+\S+/gi,
  /\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*[^\s,;]+/gi,
  /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(?:sk|pk|sb)_(?:live|test|publishable|secret)?_?[A-Za-z0-9_-]{20,}\b/gi,
];

function safeText(value) {
  if (value === null || value === undefined) return '(없음)';
  let text = String(value);
  for (const pattern of SECRET_PATTERNS) {
    text = text.replace(pattern, '[REDACTED]');
  }
  // Avoid emitting long opaque credential-like strings even if their prefix is unknown.
  text = text.replace(/\b[A-Za-z0-9_+/=-]{40,}\b/g, '[REDACTED]');
  return text.replace(/[\r\n\t]+/g, ' ').trim();
}

function projectAlert(alert) {
  return {
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: safeText(alert?.rule?.level),
    description: safeText(alert?.rule?.description),
  };
}

async function main() {
  const raw = await readFile(fixturePath, 'utf8');
  const fixture = JSON.parse(raw);

  if (!Array.isArray(fixture.alerts)) {
    throw new Error('잘못된 경보 파일: alerts 배열이 없습니다.');
  }

  const rows = fixture.alerts.map(projectAlert);
  for (const row of rows) {
    console.log(
      `시각: ${row.timestamp} | 출발 주소: ${row.sourceAddress} | 계정: ${row.account} | 규칙 수준: ${row.ruleLevel} | 설명: ${row.description}`,
    );
  }

  console.log(`확인: 경보 ${fixture.alerts.length}건, 추출 줄 ${rows.length}줄`);
  if (rows.length !== fixture.alerts.length) {
    throw new Error('경보 건수와 추출 줄 수가 일치하지 않습니다.');
  }
}

main().catch((error) => {
  console.error(`경보 읽기 실패: ${safeText(error?.message ?? '알 수 없는 오류')}`);
  process.exitCode = 1;
});
