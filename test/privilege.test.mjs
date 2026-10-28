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
const PATTERNS_PATH = join(ROOT, "xdr", "privilege", "patterns.json");
const RESULT_PATH = join(ROOT, "xdr", "privilege", "result.json");
test("심판처럼 fixture의 각 privilege 경보를 decide.mjs로 독립 판정한다", async (t) => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, "utf8"));
  assert.equal(fixture.schema, "aleph.xdr.fixture.v1");
  assert.equal(fixture.moduleKey, "privilege");
  assert.ok(fixture.alerts.length > 0);
  const savedResult = JSON.parse(await readFile(RESULT_PATH, "utf8"));
  assert.equal(savedResult.schema, "aleph.xdr.result.v1");
  assert.equal(savedResult.moduleKey, "privilege");
  const savedDecisions = new Map(savedResult.decisions.map((decision) => [decision.alertId, decision]));

  const expectedActions = new Map([
    ["pv-01", "alert"],
    ["pv-02", "block"],
    ["pv-03", "alert"],
    ["pv-04", "block"],
    ["pv-05", "block"],
    ["pv-06", "alert"],
    ["pv-07", "block"],
    ["pv-08", "alert"],
    ["pv-09", "alert"],
    ["pv-10", "alert"],
    ["pv-11", "record"],
    ["pv-12", "alert"],
    ["pv-13", "record"],
    ["pv-14", "alert"],
    ["pv-15", "record"],
    ["pv-16", "alert"],
    ["pv-17", "record"],
    ["pv-18", "record"],
    ["pv-19", "record"],
    ["pv-20", "record"],
    ["pv-21", "record"],
    ["pv-22", "record"],
    ["pv-23", "record"],
    ["pv-24", "record"],
    ["pv-25", "record"],
    ["pv-26", "record"]
  ]);
  assert.deepEqual([...expectedActions.keys()], fixture.alerts.map((alert) => alert.id));
  const expectedCounts = fixture.alerts.reduce((counts, alert) => {
    counts[expectedActions.get(alert.id)] += 1;
    return counts;
  }, { block: 0, alert: 0, record: 0 });
  assert.deepEqual(expectedCounts, { block: 4, alert: 9, record: 13 });
  assert.deepEqual(savedResult.counts, expectedCounts, "result.json 집계가 테스트 기대값과 일치해야 합니다");
  assert.deepEqual(savedResult.decisions.map((decision) => decision.alertId), fixture.alerts.map((alert) => alert.id));

  for (const alert of fixture.alerts) {
    await t.test(alert.id, () => {
      const result = decidePrivilege(alert);
      const saved = savedDecisions.get(alert.id);
      assert.ok(saved, alert.id + ": result.json에 저장된 판정이 있어야 합니다");
      assert.equal(saved.action, result.action, alert.id + ": result.json action이 실행 결과와 일치해야 합니다");
      assert.equal(saved.confidence, result.confidence, alert.id + ": result.json confidence가 실행 결과와 일치해야 합니다");
      assert.equal(saved.reason, result.reason, alert.id + ": result.json reason이 실행 결과와 일치해야 합니다");
      assert.equal(result.action, expectedActions.get(alert.id), `unexpected classification for ${alert.id}`);
      assert.ok(["block", "alert", "record"].includes(result.action));
      assert.ok(Number.isFinite(result.confidence) && result.confidence >= 0 && result.confidence <= 1);
      assert.equal(
        result.action,
        result.confidence >= 0.85 ? "block" : result.confidence >= 0.5 ? "alert" : "record"
      );
      assert.equal(typeof result.reason, "string");
      assert.ok(result.reason.length > 0);
      assert.doesNotMatch(result.reason, /user\\d{2}|acct-user/i);
    });
  }
});

test("patterns.json은 관리자 그룹 추가·처음 관측된 관리자 명령·업무 시간 밖 사용을 근거와 함께 정의한다", async () => {
  const spec = JSON.parse(await readFile(PATTERNS_PATH, "utf8"));
  const byId = new Map(spec.patterns.map((pattern) => [pattern.id, pattern]));
  assert.ok(byId.has("admin_group_addition"), "관리자 그룹 추가 패턴이 있어야 합니다");
  assert.ok(byId.has("unfamiliar_admin_command"), "처음 관측된 관리자 명령 패턴이 있어야 합니다");
  assert.ok(byId.has("off_hours_privilege_use"), "업무 시간 밖 권한 사용 패턴이 있어야 합니다");
  assert.match(byId.get("unfamiliar_admin_command").condition, /명령 자체가 처음 관측/);
  assert.match(byId.get("unfamiliar_admin_command").name, /처음 관측된 관리자 명령.*낯선 출발지.*계정/);
  assert.ok(spec.attackTechniques.some((technique) => technique.id === "T1068"));
  assert.ok(spec.attackTechniques.some((technique) => technique.id === "T1078"));
  for (const pattern of spec.patterns) {
    assert.ok(pattern.name?.trim(), pattern.id + ": name이 있어야 합니다");
    assert.ok(pattern.condition?.trim(), pattern.id + ": condition이 있어야 합니다");
    assert.ok(pattern.evidence?.trim(), pattern.id + ": evidence가 있어야 합니다");
    assert.equal(pattern.evidence.split(/\r?\n/).filter((line) => line.trim()).length, 1,
      pattern.id + ": evidence는 한 줄이어야 합니다");
  }
});

test("세 신호를 실제 판정에서 인식하고, 명령 자체가 처음 관측된 경우도 alert한다", async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, "utf8"));
  const groupAdded = decidePrivilege(fixture.alerts.find((alert) => alert.id === "pv-01"));
  assert.equal(groupAdded.action, "alert");
  assert.match(groupAdded.reason, /admin_group_addition/);

  const firstSeenCommand = decidePrivilege({
    id: "pv-test-first-seen-command",
    timestamp: "2026-10-28T01:00:00Z",
    data: { srcip: "192.0.2.99", srcuser: "test-user" },
    rule: {
      level: 7,
      description: "처음 관측된 관리자 명령이 실행됐습니다.",
      mitre: ["T1078"]
    }
  });
  assert.equal(firstSeenCommand.action, "alert");
  assert.equal(firstSeenCommand.confidence, 0.68);
  assert.match(firstSeenCommand.reason, /unfamiliar_admin_command/);
  assert.match(firstSeenCommand.reason, /명령 자체가 처음 관측/);

  const offHours = decidePrivilege({
    id: "pv-test-off-hours",
    timestamp: "2026-10-28T01:00:00Z",
    data: { srcip: "192.0.2.100", srcuser: "test-user" },
    rule: {
      level: 7,
      description: "업무 시간 밖 관리자 명령이 실행됐습니다.",
      mitre: ["T1078"]
    }
  });
  assert.equal(offHours.action, "alert");
  assert.equal(offHours.confidence, 0.72);
  assert.match(offHours.reason, /off_hours_privilege_use/);
});

test("심판의 원본 경보처럼 identity 필드가 없어도 같은 판정을 반환한다", async () => {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, "utf8"));
  for (const alert of fixture.alerts) {
    const { identity: _identity, ...withoutIdentity } = alert;
    assert.deepEqual(
      decidePrivilege(withoutIdentity),
      decidePrivilege(alert),
      `${alert.id}: identity 유무로 판정이 달라지면 안 됩니다`
    );
  }
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
    assert.ok(appendedLogLines.length > 0);
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
