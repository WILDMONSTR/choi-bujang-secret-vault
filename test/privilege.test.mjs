import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { decide as decidePrivilege } from "../xdr/privilege/decide.mjs";
import { decide as existingDecide } from "../src/decider.mjs";
import { decideWithXdr } from "../src/xdr-ztna-gate.mjs";
import { fixtureRequests } from "../scripts/fixture-7.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_PATH = join(ROOT, "xdr", "fixtures", "privilege.json");
test("privilege fixture decisions satisfy the output contract without hard-coded judge labels/counts", async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, "utf8"));
  assert.equal(fixture.schema, "aleph.xdr.fixture.v1");
  assert.equal(fixture.moduleKey, "privilege");
  const results = fixture.alerts.map((alert) => ({ alertId: alert.id, ...decidePrivilege(alert) }));
  assert.equal(results.length, fixture.alerts.length);
  assert.ok(results.every((item) => ["block", "alert", "record"].includes(item.action)));
  assert.ok(results.every((item) => Number.isFinite(item.confidence) && item.confidence >= 0 && item.confidence <= 1));
  assert.ok(results.every((item) => typeof item.reason === "string" && item.reason.length > 0));
  assert.ok(results.every((item) => !/user\d{2}|acct-user/i.test(item.reason)));
});

test("block requires high severity, valid source IP, MITRE evidence, and a trusted account ID", async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, "utf8"));
  const original = fixture.alerts.find((alert) => alert.id === "pv-04");
  const strong = {
    ...original,
    identity: { subjectId: "acct-user03", source: "trusted-directory" }
  };
  assert.equal(decidePrivilege(strong).action, "block");
  assert.equal(decidePrivilege(strong).confidence, 0.96);

  const assertNotBlocked = (alert) => assert.notEqual(decidePrivilege(alert).action, "block");

  const lowRule = { ...strong, rule: { ...strong.rule, level: 6 } };
  assertNotBlocked(lowRule);

  const noSource = { ...strong, data: { ...strong.data } };
  delete noSource.data.srcip;
  assertNotBlocked(noSource);

  const invalidSource = { ...strong, data: { ...strong.data, srcip: "203.0.113.999" } };
  assertNotBlocked(invalidSource);

  const noMitre = { ...strong, rule: { ...strong.rule, mitre: [] } };
  assertNotBlocked(noMitre);

  const noIdentity = { ...strong };
  delete noIdentity.identity;
  assertNotBlocked(noIdentity);

  const noSubject = { ...strong, identity: { source: "trusted-directory" } };
  assertNotBlocked(noSubject);

  const untrustedIdentity = {
    ...strong,
    identity: { subjectId: "acct-user03", source: "untrusted-alert" }
  };
  assertNotBlocked(untrustedIdentity);

  const bulkOriginal = fixture.alerts.find((alert) => alert.id === "pv-05");
  const bulk = {
    ...bulkOriginal,
    identity: { subjectId: "acct-user04", source: "trusted-directory" }
  };
  assert.equal(decidePrivilege(bulk).action, "block");
  const bulkWithoutIdentity = { ...bulk };
  delete bulkWithoutIdentity.identity;
  assertNotBlocked(bulkWithoutIdentity);

  const ambiguous = fixture.alerts.find((alert) => alert.id === "pv-03");
  assert.equal(decidePrivilege(ambiguous).action, "alert");
  assert.equal(decidePrivilege(fixture.alerts.find((alert) => alert.id === "pv-11")).action, "record");
  const benignFailureSource = fixture.alerts.find((alert) => alert.id === "pv-12");
  const benignFailure = {
    ...benignFailureSource,
    rule: { ...benignFailureSource.rule, description: "평소 주소에서 관리자 명령이 실패했습니다." }
  };
  assert.equal(decidePrivilege(benignFailure).action, "alert");
});

test("대응기는 5분 이내 권한 변경과 관리자 명령을 상관분석하고 계정별 15분 규칙을 쓴다", async () => {
  const temp = await mkdtemp(join(tmpdir(), "privilege-"));
  try {
    await Promise.all([
      mkdir(join(temp, "xdr", "fixtures"), { recursive: true }),
      mkdir(join(temp, "xdr", "privilege"), { recursive: true })
    ]);
    await copyFile(FIXTURE_PATH, join(temp, "xdr", "fixtures", "privilege.json"));
    await copyFile(join(ROOT, "xdr", "privilege", "decide.mjs"), join(temp, "xdr", "privilege", "decide.mjs"));
    await copyFile(join(ROOT, "xdr", "privilege", "respond.mjs"), join(temp, "xdr", "privilege", "respond.mjs"));
    await writeFile(join(temp, "xdr", "alerts.log"), "existing-log-line\n");
    const child = spawn(process.execPath, [join(temp, "xdr", "privilege", "respond.mjs")], { cwd: temp, windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const exitCode = await new Promise((resolve, reject) => {
      child.on("error", reject);
      child.on("close", resolve);
    });
    assert.equal(exitCode, 0, stderr);
    assert.match(stdout, /privilege 시험 경보: \d+건/u);
    assert.match(stdout, /판정: block \d+, alert \d+, record \d+/u);
    assert.match(stdout, /계정 세션 거부 규칙 생성\/갱신: \d+건/u);

    const ruleData = JSON.parse(await readFile(join(temp, "xdr", "privilege", "session-rules.json"), "utf8"));
    assert.equal(ruleData.schema, "aleph.xdr.session-deny.v1");
    assert.ok(ruleData.rules.length > 0);
    const user01Rule = ruleData.rules.find((rule) => rule.subjectId === "acct-user01");
    assert.ok(user01Rule);
    assert.deepEqual(user01Rule.evidenceAlertIds, ["pv-01", "pv-02"]);
    assert.equal(Date.parse(user01Rule.expiresAt) - Date.parse(user01Rule.createdAt), 15 * 60 * 1000);
    const user04Rule = ruleData.rules.find((rule) => rule.subjectId === "acct-user04");
    assert.ok(user04Rule);
    assert.deepEqual(user04Rule.evidenceAlertIds, ["pv-05"]);
    assert.equal(user04Rule.evidencePattern, "bulk_admin_group_addition");
    assert.ok(ruleData.rules.every((rule) => rule.id.startsWith("xdr-privilege-")));

    const log = await readFile(join(temp, "xdr", "alerts.log"), "utf8");
    assert.match(log, /existing-log-line/u);
    assert.doesNotMatch(log, /user\d{2}|acct-user\d{2}/i);
    const appendedLogLines = log.trim().split(/\r?\n/u).slice(1);
    const parsed = appendedLogLines.map((line) => JSON.parse(line));
    assert.equal(appendedLogLines.length, 16);
    const alertRows = parsed.filter((row) => row.action === "alert" && typeof row.alertId === "string");
    const fixtureIds = new Set(JSON.parse(await readFile(FIXTURE_PATH, "utf8")).alerts.map((alert) => alert.id));
    assert.ok(alertRows.every((row) => fixtureIds.has(row.alertId)));
    assert.ok(parsed.some((row) => row.action === "block" && row.alertIds?.includes("pv-01") && row.alertIds?.includes("pv-02")));
    assert.ok(parsed.every((row) => row.moduleKey === "privilege"));
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("ZTNA는 신뢰된 subjectId의 활성 세션 규칙만 먼저 확인하고 원래 판정기를 보존한다", async () => {
  const rulesPath = join(ROOT, "xdr", "privilege", "session-rules.json");
  let previous;
  try { previous = await readFile(rulesPath, "utf8"); }
  catch (error) { if (error?.code !== "ENOENT") throw error; }
  const at = new Date("2026-10-16T00:00:00.000Z");
  try {
    await writeFile(rulesPath, JSON.stringify({
      schema: "aleph.xdr.session-deny.v1",
      generatedAt: at.toISOString(),
      rules: [{
        id: "xdr-privilege-gate-test",
        effect: "deny",
        subjectId: "acct-user03",
        createdAt: at.toISOString(),
        expiresAt: "2099-01-01T00:00:00.000Z",
        evidenceAlertIds: ["pv-gate-test"],
        evidencePattern: "test fixture",
        confidence: 0.96
      }]
    }, null, 2) + "\n");

    const requestForBlockedAccount = { ...fixtureRequests().normal, subjectId: "acct-user03" };
    const blocked = await decideWithXdr(requestForBlockedAccount, "192.0.2.200", at);
    assert.equal(blocked.effectiveDecision, "deny");
    assert.equal(blocked.source, "xdr-privilege");
    assert.equal(blocked.evidenceAlertId, "pv-gate-test");
    assert.equal(blocked.policyDecision, null);

    const normal = fixtureRequests().normal;
    const expectedPolicy = await existingDecide(normal);
    const unaffected = await decideWithXdr(normal, "192.0.2.200", at);
    assert.equal(unaffected.source, "ztna-policy");
    assert.equal(unaffected.effectiveDecision, expectedPolicy.decision);
    assert.deepEqual(unaffected.policyDecision, expectedPolicy);
  } finally {
    if (previous === undefined) await rm(rulesPath, { force: true });
    else await writeFile(rulesPath, previous);
  }
});
