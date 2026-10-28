// 확인 전용 읽기 모듈: decide.mjs에서는 가져오지 않습니다.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(HERE, '../fixtures/exfiltration.json');

function sanitized(value) {
  const text = typeof value === 'string' ? value : typeof value === 'number' ? String(value) : '';
  return text.replace(/[\r\n\t]+/g, ' ')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+/gi, 'Bearer [REDACTED]')
    .replace(/\b(?:password|passwd|token|secret|api[-_ ]?key)\s*[:=]\s*[^\s,;]+/gi, '[REDACTED]')
    .replace(/\b(?:sk|sb_secret)_[A-Za-z0-9_-]{8,}\b/g, '[REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{48,}\b/g, '[REDACTED]')
    .slice(0, 240);
}

export async function readAlerts(file = FIXTURE) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' ||
      fixture.moduleKey !== 'exfiltration' || !Array.isArray(fixture.alerts)) {
    throw new Error('exfiltration 경보 형식이 올바르지 않습니다.');
  }
  const rows = fixture.alerts.map((alert) => ({
    timestamp: sanitized(alert?.timestamp),
    sourceAddress: sanitized(alert?.data?.srcip),
    account: sanitized(alert?.data?.srcuser),
    ruleLevel: Number.isFinite(Number(alert?.rule?.level)) ? Number(alert.rule.level) : null,
    description: sanitized(alert?.rule?.description)
  }));
  return { alertCount: fixture.alerts.length, rows };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  readAlerts().then(({ alertCount, rows }) => {
    for (const row of rows) console.log(JSON.stringify(row));
    console.log('경보 건수: ' + alertCount + ', 추출 줄 수: ' + rows.length);
    if (rows.length !== alertCount) process.exitCode = 1;
  }).catch(() => {
    console.error('경보 읽기 실패');
    process.exitCode = 1;
  });
}
