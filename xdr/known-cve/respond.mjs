import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const FIXTURE = resolve(ROOT, 'xdr/fixtures/known-cve.json');
const RULES_FILE = resolve(HERE, '../brute-force/deny-rules.json');
const LOG_FILE = resolve(ROOT, 'xdr/alerts.log');
const TTL_MS = 15 * 60 * 1000;
const CLEAR_PATTERN_NAME = 'CVE-2021-44228 원격 JNDI 조회 표식';
const REMOTE_LOOKUP_PATTERN = /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba|nds|http)\s*:\/\/[^{}\s]+\s*\}/i;

function oneLine(value) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').trim();
}
function inputValues(alert) {
  const data = alert?.data ?? {};
  const keys = ['url', 'uri', 'query', 'parameter', 'param', 'requestTarget', 'useragent', 'userAgent',
    'http_user_agent', 'header', 'headers'];
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
function hasRemoteLookup(alert) {
  return inputValues(alert).some((value) => {
    let current = String(value ?? '').replace(/\+/g, ' ');
    for (let i = 0; i < 3; i += 1) {
      if (REMOTE_LOOKUP_PATTERN.test(current)) return true;
      try {
        const next = decodeURIComponent(current);
        if (next === current) break;
        current = next.replace(/\+/g, ' ');
      } catch { break; }
    }
    return false;
  });
}
function activeRules(data, now) {
  if (data?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(data.rules)) {
    throw new Error('공용 deny-rules.json 형식이 올바르지 않습니다.');
  }
  return data.rules.filter((rule) => rule?.effect === 'deny' && typeof rule.id === 'string' &&
    typeof rule.sourceAddress === 'string' && isIP(rule.sourceAddress) !== 0 &&
    Number.isFinite(Date.parse(rule.expiresAt)) && Date.parse(rule.expiresAt) > now.getTime());
}
async function loadExistingRules(now) {
  try {
    return activeRules(JSON.parse(await readFile(RULES_FILE, 'utf8')), now);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}
function isClearCandidate(alert, output) {
  const ip = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const level = Number(alert?.rule?.level) || 0;
  return Boolean(oneLine(alert?.id)) && isIP(ip) !== 0 &&
    output?.action === 'block' && typeof output.confidence === 'number' && output.confidence >= 0.85 &&
    level >= 10 && oneLine(output.reason).includes(CLEAR_PATTERN_NAME) && hasRemoteLookup(alert);
}

export async function checkKnownCveDeny(sourceAddress, at = new Date()) {
  const ip = typeof sourceAddress === 'string' ? sourceAddress.trim() : '';
  if (isIP(ip) === 0) return null;
  const now = at instanceof Date ? at : new Date(at);
  return (await loadExistingRules(now)).find((rule) =>
    rule.sourceAddress === ip && rule.id.startsWith('xdr-known-cve-')) ?? null;
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' ||
      fixture.moduleKey !== 'known-cve' || !Array.isArray(fixture.alerts)) {
    throw new Error('known-cve 시험 경보 파일 형식이 올바르지 않습니다.');
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
        const ruleId = 'xdr-known-cve-' + evidenceId.replace(/[^A-Za-z0-9_-]/g, '-');
        denyRule = {
          id: ruleId, effect: 'deny', sourceAddress: alert.data.srcip.trim(),
          createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
          evidenceAlertId: evidenceId, evidencePattern: CLEAR_PATTERN_NAME, confidence: output.confidence
        };
        const index = rules.findIndex((rule) => rule.id === ruleId);
        if (index >= 0) rules[index] = denyRule;
        else rules.push(denyRule);
        generated += 1;
      } else {
        output = { action: 'alert', confidence: Math.min(output.confidence, 0.79),
          reason: '차단 보류: 명확한 악용 근거 부족; ' + oneLine(output.reason) };
      }
    }
    counts[output.action] += 1;
    if (output.action !== 'record') {
      logLines.push(JSON.stringify({
        at: now.toISOString(), moduleKey: 'known-cve', alertId: oneLine(alert?.id),
        action: output.action, confidence: output.confidence, reason: oneLine(output.reason),
        ...(denyRule ? { ruleId: denyRule.id, expiresAt: denyRule.expiresAt } : {})
      }));
    }
  }

  await mkdir(dirname(RULES_FILE), { recursive: true });
  await writeFile(RULES_FILE, JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1', generatedAt: now.toISOString(), rules
  }, null, 2) + '\n', 'utf8');
  if (logLines.length) {
    await mkdir(dirname(LOG_FILE), { recursive: true });
    await appendFile(LOG_FILE, logLines.join('\n') + '\n', 'utf8');
  }
  console.log('known-cve 시험 경보: ' + fixture.alerts.length + '건');
  console.log('판정: block ' + counts.block + ', alert ' + counts.alert + ', record ' + counts.record);
  console.log('차단 규칙 생성/갱신: ' + generated + '건; 현재 활성 규칙: ' + rules.length + '건');
  console.log('alerts.log 추가: ' + logLines.length + '줄');
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error('known-cve 대응 실패: ' + oneLine(error?.message ?? '알 수 없는 오류'));
    process.exitCode = 1;
  });
}
