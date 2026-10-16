import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { decide as decidePersistence } from '../xdr/persistence/decide.mjs';
import { decide as existingDecide } from '../src/decider.mjs';
import { decideWithXdr } from '../src/xdr-ztna-gate.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_PATH = join(ROOT, 'xdr', 'fixtures', 'persistence.json');
const CLEAR_IDS = ['ps-01', 'ps-02', 'ps-03', 'ps-04', 'ps-05', 'ps-06', 'ps-07', 'ps-08'];
const AMBIGUOUS_IDS = ['ps-09', 'ps-10', 'ps-11', 'ps-12', 'ps-13', 'ps-14', 'ps-15', 'ps-16'];

test('persistence fixture: 명확한 지속성 악용은 block, 애매한 변경은 alert, 정상은 record', async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, 'utf8'));
  assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey, 'persistence');
  const decisions = fixture.alerts.map((alert) => ({ alertId: alert.id, ...decidePersistence(alert) }));
  const counts = decisions.reduce((out, item) => { out[item.action] += 1; return out; }, { block: 0, alert: 0, record: 0 });

  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  assert.deepEqual(decisions.filter((item) => item.action === 'block').map((item) => item.alertId), CLEAR_IDS);
  assert.deepEqual(decisions.filter((item) => item.action === 'alert').map((item) => item.alertId), AMBIGUOUS_IDS);
  assert.deepEqual(decisions.filter((item) => item.action === 'record').map((item) => item.alertId),
    fixture.alerts.slice(16).map((alert) => alert.id));
  for (const item of decisions) {
    assert.ok(item.confidence >= 0 && item.confidence <= 1);
    assert.equal(typeof item.reason, 'string');
    assert.doesNotMatch(item.reason, /C:\\Users\\user\d+\\AppData\\Local\\Temp|helper\.exe|stay\.exe/i);
  }
});

test('명확한 징후라도 심각도·출발지·기법 근거가 빠지면 격리하지 않는다', async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, 'utf8'));
  const strong = fixture.alerts[0];
  assert.equal(decidePersistence(strong).action, 'block');
  assert.equal(decidePersistence({ ...strong, rule: { ...strong.rule, level: 6 } }).action, 'alert');
  const missingAddress = { ...strong, data: { ...strong.data } };
  delete missingAddress.data.srcip;
  assert.equal(decidePersistence(missingAddress).action, 'alert');
  assert.equal(decidePersistence({ ...strong, rule: { ...strong.rule, mitre: [] } }).action, 'alert');
  assert.equal(decidePersistence(fixture.alerts[19]).action, 'record');
});

test('persistence 대응기는 제한시간 차단 규칙과 원문을 제외한 알림 로그를 쓴다', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'persistence-'));
  try {
    const dirs = [
      join(temp, 'xdr', 'fixtures'),
      join(temp, 'xdr', 'persistence'),
      join(temp, 'xdr', 'brute-force')
    ];
    await Promise.all(dirs.map((dir) => mkdir(dir, { recursive: true })));
    await copyFile(FIXTURE_PATH, join(temp, 'xdr', 'fixtures', 'persistence.json'));
    await copyFile(join(ROOT, 'xdr', 'persistence', 'decide.mjs'), join(temp, 'xdr', 'persistence', 'decide.mjs'));
    await copyFile(join(ROOT, 'xdr', 'persistence', 'respond.mjs'), join(temp, 'xdr', 'persistence', 'respond.mjs'));
    await writeFile(join(temp, 'xdr', 'brute-force', 'deny-rules.json'), JSON.stringify({
      schema: 'aleph.xdr.deny-rules.v1',
      generatedAt: '2026-10-01T00:00:00.000Z',
      rules: [{ id: 'xdr-known-cve-existing', effect: 'deny', sourceAddress: '192.0.2.99',
        createdAt: '2026-10-01T00:00:00.000Z', expiresAt: '2099-01-01T00:00:00.000Z',
        evidenceAlertId: 'kc-existing', evidencePattern: 'existing lab rule', confidence: 0.96 }]
    }, null, 2) + '\n');
    await writeFile(join(temp, 'xdr', 'alerts.log'), 'existing-log-line\n');

    const child = spawn(process.execPath, [join(temp, 'xdr', 'persistence', 'respond.mjs')], { cwd: temp, windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const exitCode = await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', resolve);
    });
    assert.equal(exitCode, 0, stderr);
    assert.match(stdout, /persistence 시험 경보: 24건/u);
    assert.match(stdout, /판정: block 8, alert 8, record 8/u);
    assert.match(stdout, /격리 규칙 생성\/갱신: 8건/u);

    const rules = JSON.parse(await readFile(join(temp, 'xdr', 'brute-force', 'deny-rules.json'), 'utf8'));
    assert.ok(rules.rules.some((rule) => rule.id === 'xdr-known-cve-existing'));
    const newRules = rules.rules.filter((rule) => rule.id.startsWith('xdr-persistence-'));
    assert.equal(newRules.length, 8);
    assert.ok(newRules.every((rule) => Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) === 15 * 60 * 1000));
    const log = await readFile(join(temp, 'xdr', 'alerts.log'), 'utf8');
    const lines = log.trim().split(/\r?\n/u);
    assert.equal(lines.length, 17);
    assert.equal(lines[0], 'existing-log-line');
    assert.doesNotMatch(log, /C:\\Users\\user\d+\\AppData\\Local\\Temp|helper\.exe|stay\.exe/i);
    assert.ok(lines.slice(1).every((line) => {
      const item = JSON.parse(line);
      return item.moduleKey === 'persistence' && ['block', 'alert'].includes(item.action);
    }));
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('ZTNA 사전 격리는 persistence 규칙을 사용하고 원래 판정기는 그대로 유지한다', async () => {
  const rulesPath = join(ROOT, 'xdr', 'brute-force', 'deny-rules.json');
  let originalRules;
  try { originalRules = await readFile(rulesPath, 'utf8'); }
  catch (error) { if (error?.code !== 'ENOENT') throw error; }

  const at = new Date('2026-10-16T00:00:00.000Z');
  try {
    await writeFile(rulesPath, JSON.stringify({
      schema: 'aleph.xdr.deny-rules.v1',
      generatedAt: at.toISOString(),
      rules: [{
        id: 'xdr-persistence-gate-test',
        effect: 'deny',
        sourceAddress: '203.0.113.91',
        createdAt: at.toISOString(),
        expiresAt: '2099-01-01T00:00:00.000Z',
        evidenceAlertId: 'ps-gate-test',
        evidencePattern: 'test fixture',
        confidence: 0.96
      }]
    }, null, 2) + '\n');

    const isolated = await decideWithXdr(fixtureRequests().normal, '203.0.113.91', at);
    assert.equal(isolated.effectiveDecision, 'deny');
    assert.equal(isolated.source, 'xdr-persistence');
    assert.equal(isolated.evidenceAlertId, 'ps-gate-test');
    assert.equal(isolated.policyDecision, null);

    const normal = fixtureRequests().normal;
    const expectedPolicy = await existingDecide(normal);
    const unaffected = await decideWithXdr(normal, '192.0.2.200', at);
    assert.equal(unaffected.source, 'ztna-policy');
    assert.equal(unaffected.effectiveDecision, expectedPolicy.decision);
    assert.deepEqual(unaffected.policyDecision, expectedPolicy);
  } finally {
    if (originalRules === undefined) await rm(rulesPath, { force: true });
    else await writeFile(rulesPath, originalRules);
  }
});
