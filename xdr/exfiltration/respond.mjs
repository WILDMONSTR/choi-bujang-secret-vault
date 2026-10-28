import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const FIXTURE = resolve(ROOT, 'xdr/fixtures/exfiltration.json');
const PATTERN_FILE = resolve(HERE, 'patterns.json');
const RULES_FILE = resolve(HERE, '../brute-force/deny-rules.json');
const LOG_FILE = resolve(ROOT, 'xdr/alerts.log');
const TTL_MS = 15 * 60 * 1000;
const MINIMUM_BULK_BYTES = 50_000_000;
const BLOCK_MINIMUM_LEVEL = 10;

function safeId(value) {
  return typeof value === 'string' && /^[a-z0-9_-]{1,48}$/i.test(value) ? value : '';
}
function validTime(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}
function activeRules(data, at) {
  if (data?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(data.rules)) {
    throw new Error('공용 ZTNA 거부 규칙 형식이 올바르지 않습니다.');
  }
  return data.rules.filter((rule) => rule?.effect === 'deny' &&
    typeof rule.id === 'string' && isIP(rule.sourceAddress) !== 0 &&
    validTime(rule.expiresAt) && Date.parse(rule.expiresAt) > at.getTime());
}
async function readRules(at) {
  try {
    return activeRules(JSON.parse(await readFile(RULES_FILE, 'utf8')), at);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

// trustedSourceAddress는 서버/엔진이 검증한 출발지여야 하며 클라이언트 입력을 신뢰하지 않습니다.
export async function checkExfiltrationDeny(trustedSourceAddress, at = new Date()) {
  const source = typeof trustedSourceAddress === 'string' ? trustedSourceAddress.trim() : '';
  if (isIP(source) === 0) return null;
  const now = at instanceof Date ? at : new Date(at);
  if (!Number.isFinite(now.getTime())) throw new Error('Invalid rule-check time');
  return (await readRules(now)).find((rule) =>
    rule.id.startsWith('xdr-exfiltration-') && rule.sourceAddress === source) ?? null;
}

function validDecision(output) {
  return output && ['block', 'alert', 'record'].includes(output.action) &&
    Number.isFinite(output.confidence) && output.confidence >= 0 && output.confidence <= 1 &&
    typeof output.reason === 'string';
}
function candidate(alert, decision, patterns) {
  const src = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const dest = typeof alert?.data?.dstip === 'string' ? alert.data.dstip.trim() : '';
  const level = Number(alert?.rule?.level);
  const bytes = Number(alert?.data?.bytes);
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const desc = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const matched = patterns.find((p) => p.confidence >= 0.85 &&
    decision.reason.startsWith(p.name));
  if (!safeId(alert?.id) || isIP(src) === 0 || isIP(dest) === 0 ||
      decision.action !== 'block' || decision.confidence < 0.85 ||
      level < BLOCK_MINIMUM_LEVEL || !Number.isFinite(bytes) ||
      bytes < MINIMUM_BULK_BYTES || !matched ||
      !matched.techniqueIds.some((id) => mitre.includes(id)) ||
      /외부\s*전송은\s*아직\s*없|전송\s*실패|전송이\s*실패|no\s*external\s*transfer/i.test(desc)) {
    return null;
  }
  return { id: safeId(alert.id), src, pattern: matched.id };
}

export async function respond({ at = new Date(), fixturePath = FIXTURE } = {}) {
  const now = at instanceof Date ? at : new Date(at);
  if (!Number.isFinite(now.getTime())) throw new Error('Invalid response time');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  const catalog = JSON.parse(await readFile(PATTERN_FILE, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'exfiltration' ||
      !Array.isArray(fixture.alerts) || catalog?.moduleKey !== 'exfiltration' ||
      !Array.isArray(catalog.patterns)) {
    throw new Error('exfiltration 경보/패턴 형식이 올바르지 않습니다.');
  }
  const outcomes = fixture.alerts.map((alert) => {
    const decision = decide(alert);
    return { alert, decision: validDecision(decision) ? decision :
      { action: 'record', confidence: 0, reason: '판정 형식 오류' } };
  });
  // 같은 출발지에 정상·애매한 이벤트가 있으면 IP만으로 정상 요청을 함께 차단하지 않습니다.
  const otherSources = new Set(outcomes.filter(({ decision }) => decision.action !== 'block')
    .map(({ alert }) => typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : ''));
  const rules = await readRules(now);
  const counts = { block: 0, alert: 0, record: 0 };
  const log = [];
  let created = 0;

  for (const { alert, decision } of outcomes) {
    counts[decision.action] += 1;
    const match = candidate(alert, decision, catalog.patterns);
    const canDeny = match && !otherSources.has(match.src);
    let rule = null;
    if (canDeny) {
      rule = {
        id: 'xdr-exfiltration-' + match.id,
        effect: 'deny',
        sourceAddress: match.src,
        createdAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
        evidenceAlertId: match.id,
        evidencePattern: match.pattern,
        confidence: decision.confidence
      };
      const index = rules.findIndex((existing) => existing.id === rule.id);
      if (index >= 0) rules[index] = rule;
      else rules.push(rule);
      created++;
    }
    if (decision.action !== 'record') {
      // 원문 설명·계정명·목적지·자료 내용·자격 증명은 절대 로그에 복사하지 않습니다.
      log.push(JSON.stringify({
        at: now.toISOString(),
        moduleKey: 'exfiltration',
        alertId: safeId(alert?.id) || 'invalid-id',
        action: decision.action,
        confidence: decision.confidence,
        ...(rule ? { ruleId: rule.id, expiresAt: rule.expiresAt } :
          decision.action === 'block' ? { response: 'deny_rule_withheld' } : {})
      }));
    }
  }

  await mkdir(dirname(RULES_FILE), { recursive: true });
  await writeFile(RULES_FILE, JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1', generatedAt: now.toISOString(), rules
  }, null, 2) + '\n', 'utf8');
  if (log.length) {
    await mkdir(dirname(LOG_FILE), { recursive: true });
    await appendFile(LOG_FILE, log.join('\n') + '\n', 'utf8');
  }
  return { alerts: fixture.alerts.length, counts, denyRulesCreated: created, logLines: log.length };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  respond().then((result) => {
    console.log('exfiltration 시험 경보: ' + result.alerts + '건');
    console.log('판정: block ' + result.counts.block +
      ', alert ' + result.counts.alert + ', record ' + result.counts.record);
    console.log('차단 규칙 생성/갱신: ' + result.denyRulesCreated + '건');
    console.log('alerts.log 추가: ' + result.logLines + '줄');
  }).catch(() => {
    console.error('exfiltration 대응 실패');
    process.exitCode = 1;
  });
}
