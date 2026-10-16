import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const FIXTURE = resolve(ROOT, 'xdr/fixtures/persistence.json');
const RULES_FILE = resolve(HERE, '../brute-force/deny-rules.json');
const LOG_FILE = resolve(ROOT, 'xdr/alerts.log');
const TTL_MS = 15 * 60 * 1000;
const CLEAR_PATTERN_IDS = new Set([
  'new_unsigned_service_in_temp',
  'unseen_task_in_temp_off_hours',
  'unknown_startup_entry',
  'repeated_unsigned_service_registration',
  'random_task_with_temp_executable',
  'unsigned_service_binary_changed',
  'multiple_persistence_methods_same_temp_binary',
  'unknown_service_survives_reboot'
]);

function oneLine(value) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').trim();
}
function activeRules(data, now) {
  if (data?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(data.rules)) {
    throw new Error('공용 deny-rules.json 형식이 올바르지 않습니다.');
  }
  return data.rules.filter((rule) => rule?.effect === 'deny' &&
    typeof rule.id === 'string' && typeof rule.sourceAddress === 'string' &&
    isIP(rule.sourceAddress) !== 0 && Number.isFinite(Date.parse(rule.expiresAt)) &&
    Date.parse(rule.expiresAt) > now.getTime());
}
async function loadExistingRules(now) {
  try {
    return activeRules(JSON.parse(await readFile(RULES_FILE, 'utf8')), now);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}
function clearCandidate(alert, output) {
  const ip = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const level = Number(alert?.rule?.level) || 0;
  const matchedPattern = oneLine(output?.reason).match(/명확한 지속성 악용:\s*([a-z0-9_]+)/i)?.[1];
  const hasTechnique = Array.isArray(alert?.rule?.mitre) &&
    alert.rule.mitre.some((id) => id === 'T1543' || id === 'T1053');
  return Boolean(oneLine(alert?.id)) &&
    isIP(ip) !== 0 &&
    output?.action === 'block' &&
    typeof output.confidence === 'number' && output.confidence >= 0.85 &&
    level >= 10 && hasTechnique && CLEAR_PATTERN_IDS.has(matchedPattern);
}

export async function checkPersistenceDeny(sourceAddress, at = new Date()) {
  const ip = typeof sourceAddress === 'string' ? sourceAddress.trim() : '';
  if (isIP(ip) === 0) return null;
  const now = at instanceof Date ? at : new Date(at);
  return (await loadExistingRules(now)).find((rule) =>
    rule.sourceAddress === ip && rule.id.startsWith('xdr-persistence-')) ?? null;
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' ||
      fixture.moduleKey !== 'persistence' || !Array.isArray(fixture.alerts)) {
    throw new Error('persistence 시험 경보 파일 형식이 올바르지 않습니다.');
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
      if (clearCandidate(alert, output)) {
        const evidenceId = oneLine(alert.id);
        const ruleId = 'xdr-persistence-' + evidenceId.replace(/[^A-Za-z0-9_-]/g, '-');
        denyRule = {
          id: ruleId,
          effect: 'deny',
          sourceAddress: alert.data.srcip.trim(),
          createdAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
          evidenceAlertId: evidenceId,
          evidencePattern: oneLine(output.reason).replace(/^명확한 지속성 악용:\s*/, ''),
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
          reason: '격리 보류: 명확한 지속성 근거 부족; ' + oneLine(output.reason)
        };
      }
    }

    counts[output.action] += 1;
    // Raw file paths, usernames, hashes, and command lines are deliberately not logged.
    if (output.action !== 'record') {
      logLines.push(JSON.stringify({
        at: now.toISOString(),
        moduleKey: 'persistence',
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

  console.log('persistence 시험 경보: ' + fixture.alerts.length + '건');
  console.log('판정: block ' + counts.block + ', alert ' + counts.alert + ', record ' + counts.record);
  console.log('격리 규칙 생성/갱신: ' + generated + '건; 현재 활성 규칙: ' + rules.length + '건');
  console.log('alerts.log 추가: ' + logLines.length + '줄');
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error('persistence 대응 실패: ' + oneLine(error?.message ?? '알 수 없는 오류'));
    process.exitCode = 1;
  });
}
