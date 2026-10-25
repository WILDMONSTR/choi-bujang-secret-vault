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
const EXPECTED_ACTIONS = Object.freeze({
  "pv-01": "alert",
  "pv-02": "block",
  "pv-03": "alert",
  "pv-04": "block",
  "pv-05": "block",
  "pv-06": "alert",
  "pv-07": "block",
  "pv-08": "alert",
  "pv-09": "alert",
  "pv-10": "alert",
  "pv-11": "record",
  "pv-12": "record",
  "pv-13": "record",
  "pv-14": "alert",
  "pv-15": "record",
  "pv-16": "alert",
  "pv-17": "record",
  "pv-18": "record",
  "pv-19": "record",
  "pv-20": "record",
  "pv-21": "record",
  "pv-22": "record",
  "pv-23": "record",
  "pv-24": "record",
  "pv-25": "record",
  "pv-26": "record"
});
const BLOCK_IDS = Object.keys(EXPECTED_ACTIONS).filter((id) => EXPECTED_ACTIONS[id] === "block");
const ALERT_IDS = Object.keys(EXPECTED_ACTIONS).filter((id) => EXPECTED_ACTIONS[id] === "alert");
const RECORD_IDS = Object.keys(EXPECTED_ACTIONS).filter((id) => EXPECTED_ACTIONS[id] === "record");

test("privilege fixture: 명확한 권한 상승만 block, 모호한 신호는 alert, 정상은 record", async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, "utf8"));
  assert.equal(fixture.schema, "aleph.xdr.fixture.v1");
  assert.equal(fixture.moduleKey, "privilege");
  const results = fixture.alerts.map((alert) => ({ alertId: alert.id, ...decidePrivilege(alert) }));
  const counts = results.reduce((out, item) => { out[item.action] += 1; return out; }, { block: 0, alert: 0, record: 0 });
  assert.deepEqual(counts, { block: 4, alert: 8, record: 14 });
  assert.deepEqual(Object.keys(EXPECTED_ACTIONS).sort(), fixture.alerts.map((alert) => alert.id).sort());
  assert.deepEqual(results.map(({ alertId, action }) => [alertId, action]),
    fixture.alerts.map((alert) => [alert.id, EXPECTED_ACTIONS[alert.id]]));
  assert.deepEqual(results.filter((item) => item.action === "block").map((item) => item.alertId), BLOCK_IDS);
  assert.deepEqual(results.filter((item) => item.action === "alert").map((item) => item.alertId), ALERT_IDS);
  assert.deepEqual(results.filter((item) => item.action === "record").map((item) => item.alertId), RECORD_IDS);
  // 대량 관리자 그룹 추가는 필드 근거가 충분해 차단하고, 짧은 시간 안의 재추가는 알림으로 남깁니다.
  assert.match(results.find((item) => item.alertId === "pv-05").reason, /^bulk_admin_group_addition:/u);
  assert.equal(results.find((item) => item.alertId === "pv-05").confidence, 0.90);
  assert.match(results.find((item) => item.alertId === "pv-09").reason, /^ambiguous_privilege_activity:/u);
  assert.ok(results.every((item) => item.confidence >= 0 && item.confidence <= 1 && typeof item.reason === "string"));
  assert.ok(results.every((item) => !/user\d{2}|acct-user/i.test(item.reason)));
});

test("명확한 동일 경보 복합 공격은 보조 메타데이터 누락만으로 block에서 내려가지 않는다", async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, "utf8"));
  const strong = fixture.alerts.find((alert) => alert.id === "pv-04");
  assert.equal(decidePrivilege(strong).action, "block");
  assert.equal(decidePrivilege(strong).confidence, 0.96);

  const lowRule = decidePrivilege({ ...strong, rule: { ...strong.rule, level: 6 } });
  assert.equal(lowRule.action, "block");
  assert.equal(lowRule.confidence, 0.96);

  const noSource = { ...strong, data: { ...strong.data } };
  delete noSource.data.srcip;
  assert.equal(decidePrivilege(noSource).action, "block");

  assert.equal(decidePrivilege({ ...strong, rule: { ...strong.rule, mitre: [] } }).action, "block");
  assert.equal(decidePrivilege({ ...strong, identity: { subjectId: "acct-user03", source: "untrusted-alert" } }).action, "block");

  const noSubject = { ...strong, identity: { source: "trusted-directory" } };
  assert.equal(decidePrivilege(noSubject).action, "block");

  const noAccountOrSource = { ...strong, data: { ...strong.data } };
  delete noAccountOrSource.data.srcuser;
  delete noAccountOrSource.data.srcip;
  assert.equal(decidePrivilege(noAccountOrSource).action, "block");

  const ambiguous = fixture.alerts.find((alert) => alert.id === "pv-03");
  assert.equal(decidePrivilege(ambiguous).action, "alert");
  assert.equal(decidePrivilege(fixture.alerts.find((alert) => alert.id === "pv-11")).action, "record");
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
    assert.match(stdout, /privilege 시험 경보: 26건/u);
    assert.match(stdout, /판정: block 4, alert 8, record 14/u);
    assert.match(stdout, /계정 세션 거부 규칙 생성\/갱신: 4건/u);

    const ruleData = JSON.parse(await readFile(join(temp, "xdr", "privilege", "session-rules.json"), "utf8"));
    assert.equal(ruleData.schema, "aleph.xdr.session-deny.v1");
    assert.equal(ruleData.rules.length, 4);
    const user01Rule = ruleData.rules.find((rule) => rule.subjectId === "acct-user01");
    assert.ok(user01Rule);
    assert.deepEqual(user01Rule.evidenceAlertIds, ["pv-01", "pv-02"]);
    assert.equal(Date.parse(user01Rule.expiresAt) - Date.parse(user01Rule.createdAt), 15 * 60 * 1000);
    assert.ok(ruleData.rules.every((rule) => rule.id.startsWith("xdr-privilege-")));

    const log = await readFile(join(temp, "xdr", "alerts.log"), "utf8");
    assert.match(log, /existing-log-line/u);
    assert.doesNotMatch(log, /user\d{2}|acct-user\d{2}/i);
    const appendedLogLines = log.trim().split(/\r?\n/u).slice(1);
    const parsed = appendedLogLines.map((line) => JSON.parse(line));
    assert.equal(appendedLogLines.length, 16);
    const alertRows = parsed.filter((row) => row.action === "alert" && typeof row.alertId === "string");
    assert.equal(alertRows.length, 8);
    assert.deepEqual(alertRows.map((row) => row.alertId).sort(), [...ALERT_IDS].sort());
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
