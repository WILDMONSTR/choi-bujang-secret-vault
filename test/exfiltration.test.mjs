import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { readAlerts } from '../xdr/exfiltration/read-alerts.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = JSON.parse(await readFile(join(ROOT, 'xdr/fixtures/exfiltration.json'), 'utf8'));

test('경보 30건을 읽고 다섯 필드만 노출한다', async () => {
  const { alertCount, rows } = await readAlerts();
  assert.equal(alertCount, fixture.alerts.length);
  assert.equal(rows.length, fixture.alerts.length);
  assert.ok(rows.every((row) =>
    Object.keys(row).sort().join(',') ===
    'account,description,ruleLevel,sourceAddress,timestamp'));
});

test('의심스러운 자격 증명 문자열을 읽기 결과에서 제거한다', async () => {
  const tmp = await mkdtemp(join(tmpdir(), 'exfil-redact-'));
  try {
    const sensitive = {
      schema: 'aleph.xdr.fixture.v1', moduleKey: 'exfiltration',
      alerts: [{ timestamp: '2026-10-28T01:00:00Z',
        rule: { level: 4, description: 'Bearer abcdefghijklmnop1234567890 token=VISIBLE_SECRET' },
        data: { srcip: '192.0.2.8', srcuser: 'user-test', secret: 'NEVER_PRINT_THIS' }
      }]
    };
    const path = join(tmp, 'fixture.json');
    await writeFile(path, JSON.stringify(sensitive));
    const result = await readAlerts(path);
    assert.equal(result.rows.length, 1);
    assert.doesNotMatch(JSON.stringify(result), /VISIBLE_SECRET|abcdefghijklmnop1234567890|NEVER_PRINT_THIS/);
  } finally {
    await rm(tmp, { force: true, recursive: true });
  }
});

test('독립 판정기: 임계값, 정상 무차단, 애매한 시도 알림, 입력 불변성', async () => {
  const code = await readFile(join(ROOT, 'xdr/exfiltration/decide.mjs'), 'utf8');
  assert.doesNotMatch(code, /^\s*import\s/m);
  assert.doesNotMatch(code, /\b(?:readFile|writeFile|fetch|require)\s*\(/);
  const patterns = JSON.parse(await readFile(join(ROOT, 'xdr/exfiltration/patterns.json'), 'utf8'));
  assert.deepEqual(patterns.attackTechniques.map((t) => t.id), ['T1041', 'T1048']);
  assert.ok(patterns.patterns.every((p) => p.name && p.condition && p.evidence &&
    !/[\r\n]/.test(p.evidence)));
  const decisions = fixture.alerts.map((alert) => {
    const original = JSON.stringify(alert);
    const output = decide(alert);
    assert.equal(JSON.stringify(alert), original);
    assert.ok(['block', 'alert', 'record'].includes(output.action));
    assert.ok(Number.isFinite(output.confidence) && output.confidence >= 0 && output.confidence <= 1);
    assert.equal(output.action, output.confidence >= 0.85 ? 'block' :
      output.confidence >= 0.5 ? 'alert' : 'record');
    assert.equal(typeof output.reason, 'string');
    assert.ok(output.reason.length > 0 && !/[\r\n]/.test(output.reason));
    return output;
  });
  assert.ok(decisions.some((x) => x.action === 'block'));
  assert.ok(decisions.some((x) => x.action === 'alert'));
  assert.ok(decisions.some((x) => x.action === 'record'));
  for (const normalAlert of fixture.alerts.slice(20)) {
    assert.equal(decide(normalAlert).action, 'record');
  }
  for (const uncertain of fixture.alerts.slice(10, 20)) {
    assert.notEqual(decide(uncertain).action, 'block');
  }
  // 공격 표식만으로 차단하지 않습니다.
  const altered = structuredClone(fixture.alerts[0]);
  altered.data.bytes = '200';
  assert.notEqual(decide(altered).action, 'block');
  altered.data.bytes = '240000000';
  altered.rule.level = 3;
  assert.notEqual(decide(altered).action, 'block');
  altered.rule.level = 12;
  altered.rule.mitre = [];
  assert.notEqual(decide(altered).action, 'block');
});

test('respond: 격리된 저장소에서만 거부 규칙과 로그를 생성하고 기존 규칙을 보존한다', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'exfil-isolation-'));
  try {
    const xdr = join(temp, 'xdr');
    await mkdir(join(xdr, 'fixtures'), { recursive: true });
    await mkdir(join(xdr, 'exfiltration'), { recursive: true });
    await mkdir(join(xdr, 'brute-force'), { recursive: true });
    await copyFile(join(ROOT, 'xdr/fixtures/exfiltration.json'), join(xdr, 'fixtures/exfiltration.json'));
    for (const name of ['decide.mjs', 'patterns.json', 'respond.mjs']) {
      await copyFile(join(ROOT, 'xdr/exfiltration', name), join(xdr, 'exfiltration', name));
    }
    const rulesFile = join(xdr, 'brute-force/deny-rules.json');
    await writeFile(rulesFile, JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1',
      generatedAt: '2026-10-28T00:00:00Z',
      rules: [{
        id: 'xdr-existing-preserve-me', effect: 'deny', sourceAddress: '203.0.113.251',
        createdAt: '2026-10-28T00:00:00Z', expiresAt: '2099-01-01T00:00:00Z',
        evidenceAlertId: 'existing-alert', confidence: 0.95
      }]
    }));
    const executable = join(xdr, 'exfiltration/respond.mjs');
    const child = spawn(process.execPath, [executable], { cwd: temp });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const exit = await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', resolve);
    });
    assert.equal(exit, 0, stderr);
    assert.match(stdout, /차단 규칙 생성\/갱신:\s*\d+건/);
    const rules = JSON.parse(await readFile(rulesFile, 'utf8')).rules;
    assert.ok(rules.some((r) => r.id === 'xdr-existing-preserve-me'));
    const added = rules.filter((r) => r.id.startsWith('xdr-exfiltration-'));
    assert.ok(added.length > 0);
    const normalSources = new Set(fixture.alerts.slice(20).map((a) => a.data.srcip));
    assert.ok(added.every((r) =>
      !normalSources.has(r.sourceAddress) &&
      r.effect === 'deny' && r.confidence >= 0.85 &&
      r.evidenceAlertId && r.evidencePattern &&
      Date.parse(r.expiresAt) - Date.parse(r.createdAt) === 15 * 60 * 1000));
    const { checkExfiltrationDeny } = await import(pathToFileURL(executable).href);
    assert.ok(await checkExfiltrationDeny(added[0].sourceAddress));
    assert.equal(await checkExfiltrationDeny('192.0.2.78'), null);
    assert.equal(await checkExfiltrationDeny(added[0].sourceAddress, new Date('2099-01-01')), null);
    const alerts = (await readFile(join(xdr, 'alerts.log'), 'utf8')).trim().split(/\r?\n/);
    assert.ok(alerts.length > 0);
    for (const line of alerts) {
      const message = JSON.parse(line);
      assert.ok(['alert', 'block'].includes(message.action));
      assert.equal(message.moduleKey, 'exfiltration');
      assert.equal(message.account, undefined);
      assert.equal(message.sourceAddress, undefined);
      assert.equal(message.description, undefined);
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
