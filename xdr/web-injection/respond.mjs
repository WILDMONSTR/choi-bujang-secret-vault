import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const FIXTURE = resolve(ROOT, 'xdr/fixtures/web-injection.json');
// 기존 src/xdr-ztna-gate.mjs가 읽는 공용 거부 규칙 저장소를 사용합니다.
const RULES_FILE = resolve(HERE, '../brute-force/deny-rules.json');
const LOG_FILE = resolve(ROOT, 'xdr/alerts.log');
const TTL_MS = 15 * 60 * 1000;
const PATTERN_NAMES = [
  '요청 인자 내 SQL 구문 반복',
  '요청 인자 내 스크립트 태그 주입 표식 반복',
  '요청 인자 내 경로 거슬러 올라가기 표식 반복'
];

function oneLine(value) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').trim();
}
function countOf(alert, description) {
  const raw = alert?.data?.count;
  if (raw !== undefined && raw !== null && String(raw).trim() !== '') {
    const count = Number(raw);
    if (Number.isFinite(count) && count >= 0) return count;
  }
  const match = description.match(/(\d+)\s*(?:번|회|건)/);
  return match ? Number(match[1]) : null;
}
function activeRules(data, now) {
  if (data?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(data.rules)) {
    throw new Error('공용 deny-rules.json 형식이 올바르지 않습니다.');
  }
  return data.rules.filter((rule) =>
    rule?.effect === 'deny' &&
    typeof rule.id === 'string' &&
    typeof rule.sourceAddress === 'string' &&
    isIP(rule.sourceAddress) !== 0 &&
    Number.isFinite(Date.parse(rule.expiresAt)) &&
    Date.parse(rule.expiresAt) > now.getTime()
  );
}
async function loadExistingRules(now) {
  try {
    const content = await readFile(RULES_FILE, 'utf8');
    return activeRules(JSON.parse(content), now);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}
function isClearCandidate(alert, output) {
  const description = oneLine(alert?.rule?.description);
  const ip = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const count = countOf(alert, description);
  const level = Number(alert?.rule?.level) || 0;
  const reason = oneLine(output?.reason);
  const hasNamedPattern = PATTERN_NAMES.some((name) => reason.includes(name));
  const noRepetition = /반복은\s*없|반복되지\s*않|not\s+repeated|no\s+repetition/i.test(description);

  return Boolean(oneLine(alert?.id)) &&
    isIP(ip) !== 0 &&
    output?.action === 'block' &&
    typeof output.confidence === 'number' && output.confidence >= 0.85 &&
    level >= 10 &&
    count !== null && count >= 5 &&
    hasNamedPattern &&
    !noRepetition;
}

export async function checkWebInjectionDeny(sourceAddress, at = new Date()) {
  const ip = typeof sourceAddress === 'string' ? sourceAddress.trim() : '';
  if (isIP(ip) === 0) return null;
  const now = at instanceof Date ? at : new Date(at);
  const rules = await loadExistingRules(now);
  return rules.find((rule) => rule.sourceAddress === ip &&
    typeof rule.id === 'string' && rule.id.startsWith('xdr-web-injection-')) ?? null;
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' ||
      fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('시험 경보 파일 형식이 올바르지 않습니다.');
  }

  const now = new Date();
  const rules = await loadExistingRules(now);
  const counts = { block: 0, alert: 0, record: 0 };
  const logLines = [];
  let generated = 0;

  for (const alert of fixture.alerts) {
    let output = await decide(alert);
    if (!output || !['block', 'alert', 'record'].includes(output.action) ||
        typeof output.confidence !== 'number' || !Number.isFinite(output.confidence) ||
        output.confidence < 0 || output.confidence > 1 || typeof output.reason !== 'string') {
      output = { action: 'record', confidence: 0, reason: '판정 결과 형식 오류' };
    }

    let denyRule = null;
    if (output.action === 'block') {
      if (isClearCandidate(alert, output)) {
        const evidenceId = oneLine(alert.id);
        const ruleId = 'xdr-web-injection-' + evidenceId.replace(/[^A-Za-z0-9_-]/g, '-');
        denyRule = {
          id: ruleId,
          effect: 'deny',
          sourceAddress: alert.data.srcip.trim(),
          createdAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
          evidenceAlertId: evidenceId,
          evidencePattern: oneLine(output.reason).replace(/^패턴:\s*/, ''),
          confidence: output.confidence
        };
        const index = rules.findIndex((rule) => rule.id === ruleId);
        if (index >= 0) rules[index] = denyRule;
        else rules.push(denyRule);
        generated += 1;
      } else {
        output = {
          action: 'alert',
          confidence: Math.min(output.confidence, 0.79),
          reason: '차단 보류: 명확한 웹 주입 근거 부족; ' + oneLine(output.reason)
        };
      }
    }

    counts[output.action] += 1;
    // 요청 URL·인자 원문은 기록하지 않습니다. alert/block 결과만 한 줄씩 append합니다.
    if (output.action !== 'record') {
      logLines.push(JSON.stringify({
        at: now.toISOString(),
        moduleKey: 'web-injection',
        alertId: oneLine(alert?.id),
        action: output.action,
        confidence: output.confidence,
        reason: oneLine(output.reason),
        ...(denyRule ? { ruleId: denyRule.id, expiresAt: denyRule.expiresAt } : {})
      }));
    }
  }

  await mkdir(dirname(RULES_FILE), { recursive: true });
  await writeFile(RULES_FILE, JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    generatedAt: now.toISOString(),
    rules
  }, null, 2) + '\n', 'utf8');
  if (logLines.length) {
    await mkdir(dirname(LOG_FILE), { recursive: true });
    await appendFile(LOG_FILE, logLines.join('\n') + '\n', 'utf8');
  }

  console.log('시험 경보: ' + fixture.alerts.length + '건');
  console.log('판정: block ' + counts.block + ', alert ' + counts.alert + ', record ' + counts.record);
  console.log('차단 규칙 생성/갱신: ' + generated + '건; 현재 활성 규칙: ' + rules.length + '건');
  console.log('alerts.log 추가: ' + logLines.length + '줄');
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error('웹 주입 대응 실패: ' + oneLine(error?.message ?? '알 수 없는 오류'));
    process.exitCode = 1;
  });
}
