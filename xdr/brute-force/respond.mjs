import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const FIXTURE = resolve(ROOT, 'xdr/fixtures/brute-force.json');
const RULES_FILE = resolve(HERE, 'deny-rules.json');
const LOG_FILE = resolve(ROOT, 'xdr/alerts.log');
const TTL_MS = 15 * 60 * 1000;
const RAPID_NAME = '짧은 시간 내 동일 주소의 연속 로그인 실패';
const SPRAY_NAME = '동일 주소에서 여러 계정에 같은 비밀번호 대입';

function oneLine(value) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').trim();
}
function descOf(alert) {
  return oneLine(alert?.rule?.description);
}
function countOf(alert, desc) {
  const raw = alert?.data?.count;
  if (raw !== undefined && raw !== null && String(raw).trim() !== '') {
    const n = Number(raw);
    if (Number.isFinite(n) && n >= 0) return n;
  }
  const m = desc.match(/실패\s*(?:가|는)?\s*(\d+)\s*건|(\d+)\s*(?:login\s+)?failures?/i);
  return m ? Number(m[1] ?? m[2]) : null;
}
function minutesOf(desc) {
  const m = desc.match(/(\d+)\s*분\s*(?:안(?:에)?|동안|이내|내에?)/);
  return m ? Number(m[1]) : null;
}
function isClearCandidate(alert, out) {
  const desc = descOf(alert);
  const ip = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const count = countOf(alert, desc);
  const minutes = minutesOf(desc);
  const reason = oneLine(out?.reason);

  if (!oneLine(alert?.id) || isIP(ip) === 0) return false;
  if (out?.action !== 'block' || out.confidence < 0.85) return false;
  if ((Number(alert?.rule?.level) || 0) < 10) return false;
  if (!/실패|login failed|login failure|authentication failed|failed login/i.test(desc)) return false;
  if (/실패[^.!?\n]{0,80}(?:뒤|이후|후에)\s*(?:다시\s*)?(?:로그인\s*)?성공|성공했습니다|로그인이\s*성공|로그인에\s*성공/i.test(desc)) return false;

  if (reason.includes(RAPID_NAME)) {
    return count !== null && count >= 30 && minutes !== null && minutes >= 1 && minutes <= 3;
  }
  if (reason.includes(SPRAY_NAME)) {
    const accounts = alert?.data?.accounts;
    const several = (Array.isArray(accounts) && accounts.length > 1) ||
      (typeof accounts === 'string' && accounts.split(/[,;|\s]+/).filter(Boolean).length > 1) ||
      /여러\s*계정|서로\s*다른\s*계정|계정\s*\d+\s*개|다른\s*계정(?:들)?/i.test(desc);
    return several &&
      /같은\s*비밀번호|동일한?\s*비밀번호|same\s+password|common\s+password/i.test(desc) &&
      /연속|이어졌|이어집|반복|consecutive|repeated/i.test(desc) &&
      minutes !== null && minutes >= 1 && minutes <= 5;
  }
  return false;
}

async function activeRules(now) {
  let data;
  try {
    data = JSON.parse(await readFile(RULES_FILE, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  if (data?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(data.rules)) {
    throw new Error('deny-rules.json 형식이 올바르지 않습니다.');
  }
  return data.rules.filter((r) => r?.effect === 'deny' &&
    typeof r.id === 'string' && typeof r.sourceAddress === 'string' &&
    isIP(r.sourceAddress) !== 0 && Number.isFinite(Date.parse(r.expiresAt)) &&
    Date.parse(r.expiresAt) > now.getTime());
}

// 신뢰된 서버/엔진이 확인한 출발지 주소로 호출합니다. 요청 본문의 IP를 넘기지 마세요.
export async function checkZtnaDeny(sourceAddress, at = new Date()) {
  const ip = typeof sourceAddress === 'string' ? sourceAddress.trim() : '';
  if (isIP(ip) === 0) return null;
  const now = at instanceof Date ? at : new Date(at);
  return (await activeRules(now)).find((r) => r.sourceAddress === ip) ?? null;
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'brute-force' || !Array.isArray(fixture.alerts)) {
    throw new Error('시험 경보 파일 형식이 올바르지 않습니다.');
  }

  const now = new Date();
  const rules = await activeRules(now);
  const counts = { block: 0, alert: 0, record: 0 };
  const log = [];
  let generated = 0;

  for (const alert of fixture.alerts) {
    let out = await decide(alert);
    if (!out || !['block', 'alert', 'record'].includes(out.action) ||
        typeof out.confidence !== 'number' || !Number.isFinite(out.confidence) ||
        out.confidence < 0 || out.confidence > 1 || typeof out.reason !== 'string') {
      out = { action: 'record', confidence: 0, reason: '판정 결과 형식 오류' };
    }

    let rule = null;
    if (out.action === 'block') {
      if (isClearCandidate(alert, out)) {
        const id = oneLine(alert.id);
        const ruleId = 'xdr-brute-force-' + id.replace(/[^A-Za-z0-9_-]/g, '-');
        rule = {
          id: ruleId,
          effect: 'deny',
          sourceAddress: alert.data.srcip.trim(),
          createdAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
          evidenceAlertId: id,
          evidencePattern: oneLine(out.reason).replace(/^패턴:\s*/, ''),
          confidence: out.confidence
        };
        const index = rules.findIndex((r) => r.id === ruleId);
        if (index >= 0) rules[index] = rule;
        else rules.push(rule);
        generated += 1;
      } else {
        out = {
          action: 'alert',
          confidence: Math.min(out.confidence, 0.79),
          reason: '차단 보류: 시간·실패 근거 부족; ' + oneLine(out.reason)
        };
      }
    }

    counts[out.action] += 1;
    if (out.action !== 'record') {
      log.push(JSON.stringify({
        at: now.toISOString(),
        alertId: oneLine(alert?.id),
        action: out.action,
        confidence: out.confidence,
        reason: oneLine(out.reason),
        ...(rule ? { ruleId: rule.id, expiresAt: rule.expiresAt } : {})
      }));
    }
  }

  await mkdir(dirname(LOG_FILE), { recursive: true });
  await writeFile(RULES_FILE, JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    generatedAt: now.toISOString(),
    rules
  }, null, 2) + '\n', 'utf8');
  if (log.length) await appendFile(LOG_FILE, log.join('\n') + '\n', 'utf8');

  console.log('시험 경보: ' + fixture.alerts.length + '건');
  console.log('판정: block ' + counts.block + ', alert ' + counts.alert + ', record ' + counts.record);
  console.log('차단 규칙 생성/갱신: ' + generated + '건; 현재 활성 규칙: ' + rules.length + '건');
  console.log('alerts.log 추가: ' + log.length + '줄');
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error('XDR 응답 처리 실패: ' + oneLine(error?.message ?? '알 수 없는 오류'));
    process.exitCode = 1;
  });
}
