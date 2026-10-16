import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { decide as decideKnownCve } from '../xdr/known-cve/decide.mjs';
import { decide as existingDecide } from '../src/decider.mjs';
import { decideWithXdr } from '../src/xdr-ztna-gate.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_PATH = join(ROOT, 'xdr', 'fixtures', 'known-cve.json');
const EXPECTED_CLEAR_IDS = ['kc-01', 'kc-02', 'kc-03', 'kc-04', 'kc-05', 'kc-06', 'kc-07', 'kc-08'];
const EXPECTED_AMBIGUOUS_IDS = ['kc-09', 'kc-10', 'kc-11', 'kc-12', 'kc-13', 'kc-14', 'kc-15', 'kc-16'];

test('known-cve fixture: 명확한 악용만 block, 애매한 표식은 alert, 정상은 record', async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, 'utf8'));
  assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey, 'known-cve');
  const results = fixture.alerts.map((alert) => ({ alertId: alert.id, ...decideKnownCve(alert) }));
  const counts = results.reduce((out, result) => { out[result.action] += 1; return out; }, { block: 0, alert: 0, record: 0 });
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  assert.deepEqual(results.filter((item) => item.action === 'block').map((item) => item.alertId), EXPECTED_CLEAR_IDS);
  assert.deepEqual(results.filter((item) => item.action === 'alert').map((item) => item.alertId), EXPECTED_AMBIGUOUS_IDS);
  assert.deepEqual(results.filter((item) => item.action === 'record').map((item) => item.alertId),
    fixture.alerts.slice(16).map((alert) => alert.id));
  for (const item of results) {
    assert.deepEqual(Object.keys(item).sort(), ['action', 'alertId', 'confidence', 'reason']);
    assert.ok(item.confidence >= 0 && item.confidence <= 1);
    assert.equal(typeof item.reason, 'string');
    assert.doesNotMatch(item.reason, /jndi:ldap:\/\/|203\.0\.113\.9\/x/i);
  }
});

test('단독 CVE 이름·약한 정황·근거 누락은 block이 아니라 alert', async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, 'utf8'));
  const strong = fixture.alerts[0];
  const lowSeverity = { ...strong, rule: { ...strong.rule, level: 6 } };
  const noSource = { ...strong, data: { ...strong.data } };
  delete noSource.data.srcip;
  assert.equal(decideKnownCve(strong).action, 'block');
  assert.equal(decideKnownCve(lowSeverity).action, 'alert');
  assert.equal(decideKnownCve(noSource).action, 'alert');
  assert.equal(decideKnownCve(fixture.alerts[8]).action, 'alert');
  assert.equal(decideKnownCve(fixture.alerts[18]).action, 'record');
});

test('known-cve 대응기는 기존 deny 규칙을 유지하고 원문 없이 로그를 남긴다', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'known-cve-'));
  try {
    const dirs = [join(temp, 'xdr', 'fixtures'), join(temp, 'xdr', 'known-cve'), join(temp, 'xdr', 'brute-force')];
    await Promise.all(dirs.map((dir) => mkdir(dir, { recursive: true })));
    await copyFile(FIXTURE_PATH, join(temp, 'xdr', 'fixtures', 'known-cve.json'));
    await copyFile(join(ROOT, 'xdr', 'known-cve', 'decide.mjs'), join(temp, 'xdr', 'known-cve', 'decide.mjs'));
    await copyFile(join(ROOT, 'xdr', 'known-cve', 'respond.mjs'), join(temp, 'xdr', 'known-cve', 'respond.mjs'));
    await writeFile(join(temp, 'xdr', 'brute-force', 'deny-rules.json'), JSON.stringify({
      schema: 'aleph.xdr.deny-rules.v1',
      generatedAt: '2026-10-01T00:00:00.000Z',
      rules: [{ id: 'xdr-brute-force-existing', effect: 'deny', sourceAddress: '192.0.2.99',
        createdAt: '2026-10-01T00:00:00.000Z', expiresAt: '2099-01-01T00:00:00.000Z',
        evidenceAlertId: 'bf-existing', evidencePattern: 'existing lab rule', confidence: 0.9 }]
    }, null, 2) + '\n');
    await writeFile(join(temp, 'xdr', 'alerts.log'), 'existing-log-line\n');
    const child = spawn(process.execPath, [join(temp, 'xdr', 'known-cve', 'respond.mjs')], { cwd: temp, windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const exitCode = await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', resolve);
    });
    assert.equal(exitCode, 0, stderr);
    assert.match(stdout, /known-cve 시험 경보: 24건/u);
    assert.match(stdout, /판정: block 8, alert 8, record 8/u);
    assert.match(stdout, /차단 규칙 생성\/갱신: 8건/u);
    const rules = JSON.parse(await readFile(join(temp, 'xdr', 'brute-force', 'deny-rules.json'), 'utf8'));
    assert.ok(rules.rules.some((rule) => rule.id === 'xdr-brute-force-existing'));
    const newRules = rules.rules.filter((rule) => rule.id.startsWith('xdr-known-cve-'));
    assert.equal(newRules.length, 8);
    assert.ok(newRules.every((rule) => Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) === 15 * 60 * 1000));
    const log = await readFile(join(temp, 'xdr', 'alerts.log'), 'utf8');
    const lines = log.trim().split(/\r?\n/u);
    assert.equal(lines.length, 17);
    assert.equal(lines[0], 'existing-log-line');
    assert.doesNotMatch(log, /jndi:ldap:\/\/|203\.0\.113\.9\/x/iu);
    assert.ok(lines.slice(1).every((line) => {
      const item = JSON.parse(line);
      return item.moduleKey === 'known-cve' && ['block', 'alert'].includes(item.action);
    }));
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('ZTNA 게이트에 known-cve 사전 확인을 추가하고 기본 판정을 보존한다', async () => {
  const rulesPath = join(ROOT, 'xdr', 'brute-force', 'deny-rules.json');
  let oldRules;
  try { oldRules = await readFile(rulesPath, 'utf8'); }
  catch (error) { if (error?.code !== 'ENOENT') throw error; }
  const at = new Date('2026-10-16T00:00:00.000Z');
  const common = { effect: 'deny', createdAt: at.toISOString(), expiresAt: '2099-01-01T00:00:00.000Z', confidence: 0.96 };
  const rules = [
    { ...common, id: 'xdr-brute-force-test', sourceAddress: '198.51.100.90', evidenceAlertId: 'bf-test' },
    { ...common, id: 'xdr-web-injection-test', sourceAddress: '192.0.2.90', evidenceAlertId: 'wi-test' },
    { ...common, id: 'xdr-known-cve-test', sourceAddress: '203.0.113.90', evidenceAlertId: 'kc-test' }
  ];
  try {
    await writeFile(rulesPath, JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', generatedAt: at.toISOString(), rules }, null, 2) + '\n');
    for (const [sourceAddress, expectedSource, evidenceAlertId] of [
      ['198.51.100.90', 'xdr-brute-force', 'bf-test'],
      ['192.0.2.90', 'xdr-web-injection', 'wi-test'],
      ['203.0.113.90', 'xdr-known-cve', 'kc-test']
    ]) {
      const output = await decideWithXdr(fixtureRequests().normal, sourceAddress, at);
      assert.equal(output.effectiveDecision, 'deny');
      assert.equal(output.source, expectedSource);
      assert.equal(output.evidenceAlertId, evidenceAlertId);
      assert.equal(output.policyDecision, null);
    }
    const normal = fixtureRequests().normal;
    const expectedPolicy = await existingDecide(normal);
    const output = await decideWithXdr(normal, '192.0.2.200', at);
    assert.equal(output.source, 'ztna-policy');
    assert.equal(output.effectiveDecision, expectedPolicy.decision);
    assert.deepEqual(output.policyDecision, expectedPolicy);
  } finally {
    if (oldRules === undefined) await rm(rulesPath, { force: true });
    else await writeFile(rulesPath, oldRules);
  }
});
