import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { decide } from "./decide.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const FIXTURE = resolve(ROOT, "xdr/fixtures/privilege.json");
const SESSION_RULES_FILE = resolve(HERE, "session-rules.json");
const LOG_FILE = resolve(ROOT, "xdr/alerts.log");
const IDENTITY_FILE = resolve(HERE, "fixture-identity.json");
const DENY_TABLE = "xdr_privilege_session_rules";
let fixtureIdentityByAlert = new Map();
const TTL_MS = 15 * 60 * 1000;
const CORRELATION_MS = 5 * 60 * 1000;

function oneLine(value) {
  return String(value ?? "").replace(/[\r\n\t]+/g, " ").trim();
}
function trustedSubject(alert) {
  // Fixture identity is held separately so the original Wazuh alerts stay byte-for-byte unchanged.
  // Live Wazuh alerts may instead carry their own trusted-directory identity.
  const embedded = alert?.identity;
  const mapped = fixtureIdentityByAlert.get(oneLine(alert?.id));
  const identity = embedded ?? mapped;
  const subjectId = oneLine(identity?.subjectId);
  if (identity?.source !== "trusted-directory" ||
      !/^[A-Za-z0-9._:-]{1,128}$/.test(subjectId)) return "";
  if (mapped && (mapped.srcuser !== oneLine(alert?.data?.srcuser) ||
                 mapped.subjectId !== subjectId)) return "";
  return subjectId;
}
function isAdminGroup(alert) {
  const raw = oneLine(alert?.data?.group);
  if (raw) return /^(?:administrators?|admins?|domain admins?|enterprise admins?|sudoers?|wheel|관리자|관리자그룹)$/i.test(raw);
  return /관리자 그룹|administrator group|admin group|domain admins?/i.test(oneLine(alert?.rule?.description))
    && !/관리자 그룹은 아닙니다|not an? admin(?:istrator)? group/i.test(oneLine(alert?.rule?.description));
}
function groupAddition(alert) {
  return isAdminGroup(alert)
    && /추가|들어가|가입|다시 관리자|재등록|멤버로|added|joined|re-added/i.test(oneLine(alert?.rule?.description));
}
function adminCommand(alert) {
  return /관리자 명령|권한 명령|관리자 권한.{0,18}명령|명령.{0,16}(?:실행|수행)|(?:실행|수행).{0,16}명령|admin command|administrator command|privileged command|command.{0,20}(?:admin|elevat)/i.test(oneLine(alert?.rule?.description));
}
function validAddress(alert) {
  return typeof alert?.data?.srcip === "string" && isIP(alert.data.srcip.trim()) !== 0;
}
function activeRules(data, now) {
  if (data?.schema !== "aleph.xdr.session-deny.v1" || !Array.isArray(data.rules)) {
    throw new Error("privilege session-rules.json 형식이 올바르지 않습니다.");
  }
  return data.rules.filter((rule) => rule?.effect === "deny"
    && typeof rule.id === "string"
    && typeof rule.subjectId === "string"
    && /^[A-Za-z0-9._:-]{1,128}$/.test(rule.subjectId)
    && Number.isFinite(Date.parse(rule.expiresAt))
    && Date.parse(rule.expiresAt) > now.getTime());
}
async function loadExistingRules(now) {
  try {
    return activeRules(JSON.parse(await readFile(SESSION_RULES_FILE, "utf8")), now);
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}
function safeDecision(alert) {
  try {
    // 이 대응 시뮬레이터의 고정 fixture 계정 매핑을 신뢰된 subject ID로 판정기에 전달합니다.
    // 심판이 단독으로 호출하는 decide()는 이런 보강 없이 입력 경보의 identity를 직접 검증합니다.
    const subjectId = trustedSubject(alert);
    const decisionAlert = !alert?.identity && subjectId
      ? { ...alert, identity: { subjectId, source: "trusted-directory" } }
      : alert;
    const value = decide(decisionAlert);
    if (value && ["block", "alert", "record"].includes(value.action)
        && Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1
        && typeof value.reason === "string") return value;
  } catch {}
  return { action: "record", confidence: 0, reason: "판정 결과 형식 오류" };
}
function createCandidate(map, subjectId, evidenceIds, evidencePattern, confidence) {
  const current = map.get(subjectId);
  const uniqueIds = [...new Set(evidenceIds.map(oneLine).filter(Boolean))];
  if (!current || uniqueIds.length > current.evidenceAlertIds.length || confidence > current.confidence) {
    map.set(subjectId, { subjectId, evidenceAlertIds: uniqueIds, evidencePattern, confidence });
  }
}

export async function checkPrivilegeSessionDeny(subjectId, at = new Date(), db = null) {
  const id = typeof subjectId === "string" ? subjectId.trim() : "";
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(id)) return null;
  const now = at instanceof Date ? at : new Date(at);
  if (!Number.isFinite(now.getTime())) throw new Error("Invalid rule-check time");
  if (db) {
    // The persistent table is authoritative for deployed API requests.
    // Never fall back to local files if the database read fails.
    const { data, error } = await db.from(DENY_TABLE)
      .select("rule_id,subject_id,expires_at,evidence_alert_ids,evidence_pattern,confidence")
      .eq("subject_id", id).gt("expires_at", now.toISOString())
      .limit(1).maybeSingle();
    if (error) throw new Error("Privilege rule store unavailable");
    if (!data) return null;
    if (typeof data.rule_id !== "string" || !data.rule_id.startsWith("xdr-privilege-") ||
        data.subject_id !== id || !Number.isFinite(Date.parse(data.expires_at)) ||
        Date.parse(data.expires_at) <= now.getTime()) throw new Error("Invalid privilege rule");
    return { id: data.rule_id, effect: "deny", subjectId: data.subject_id,
      expiresAt: data.expires_at, evidenceAlertIds: data.evidence_alert_ids,
      evidencePattern: data.evidence_pattern, confidence: data.confidence };
  }
  return (await loadExistingRules(now)).find((rule) =>
    rule.subjectId === id && rule.id.startsWith("xdr-privilege-")) ?? null;
}

async function persistRulesToDatabase(rules) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error("SUPABASE_URL and SUPABASE_SECRET_KEY are required for --persist");
  // Only the explicit --persist command can write to production; tests never do.
  const { createClient } = await import("@supabase/supabase-js");
  const db = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
  });
  const rows = rules.map((rule) => ({
    subject_id: rule.subjectId,
    rule_id: rule.id,
    created_at: rule.createdAt,
    expires_at: rule.expiresAt,
    evidence_alert_ids: rule.evidenceAlertIds,
    evidence_pattern: rule.evidencePattern,
    confidence: rule.confidence
  }));
  if (!rows.length) return;
  const { error } = await db.from(DENY_TABLE).upsert(rows, { onConflict: "subject_id" });
  if (error) throw new Error("Failed to persist privilege deny rules");
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE, "utf8"));
  const fixtureIdentity = JSON.parse(await readFile(IDENTITY_FILE, "utf8"));
  if (fixtureIdentity?.schema !== "aleph.xdr.fixture-identity.v1" ||
      fixtureIdentity.moduleKey !== "privilege" || !Array.isArray(fixtureIdentity.accounts)) {
    throw new Error("privilege fixture identity evidence format is invalid");
  }
  fixtureIdentityByAlert = new Map(fixtureIdentity.accounts.map((entry) => [entry.alertId, entry]));
  if (fixtureIdentityByAlert.size !== fixture.alerts?.length ||
      fixture.alerts.some((alert) => !trustedSubject(alert))) {
    throw new Error("privilege fixture identity evidence is incomplete");
  }
  if (fixture?.schema !== "aleph.xdr.fixture.v1" || fixture.moduleKey !== "privilege" || !Array.isArray(fixture.alerts)) {
    throw new Error("privilege 시험 경보 파일 형식이 올바르지 않습니다.");
  }

  const now = new Date();
  const currentRules = await loadExistingRules(now);
  const counts = { block: 0, alert: 0, record: 0 };
  const outputs = [];
  const logLines = [];
  const candidates = new Map();

  for (const alert of fixture.alerts) {
    const decision = safeDecision(alert);
    outputs.push({ alert, decision });
    counts[decision.action] += 1;
    const subjectId = trustedSubject(alert);
    if (decision.action === "block" && decision.confidence >= 0.85 && subjectId && validAddress(alert)
        && Number(alert?.rule?.level) >= 10
        && Array.isArray(alert?.rule?.mitre)
        && alert.rule.mitre.some((id) => ["T1078", "T1068"].includes(id))) {
      createCandidate(candidates, subjectId, [alert.id],
        decision.reason.includes("recent_elevation_then_admin_command")
          ? "recent_elevation_then_admin_command"
          : decision.reason.includes("bulk_admin_group_addition")
            ? "bulk_admin_group_addition"
            : "admin_group_added_then_admin_command",
        decision.confidence);
    }

    if (decision.action !== "record") {
      logLines.push(JSON.stringify({
        at: now.toISOString(),
        moduleKey: "privilege",
        alertId: oneLine(alert?.id),
        action: decision.action,
        confidence: decision.confidence,
        reason: oneLine(decision.reason)
      }));
    }
  }

  // Correlate separate account/group-change and admin-command alerts over a bounded window.
  for (let i = 0; i < fixture.alerts.length; i += 1) {
    const left = fixture.alerts[i];
    for (let j = i + 1; j < fixture.alerts.length; j += 1) {
      const right = fixture.alerts[j];
      const leftSubject = trustedSubject(left);
      if (!leftSubject || leftSubject !== trustedSubject(right)) continue;
      if (!validAddress(left) || !validAddress(right) || left.data.srcip.trim() !== right.data.srcip.trim()) continue;
      if (!oneLine(left.data.srcuser) || oneLine(left.data.srcuser) !== oneLine(right.data.srcuser)) continue;
      const leftTime = Date.parse(left.timestamp);
      const rightTime = Date.parse(right.timestamp);
      if (!Number.isFinite(leftTime) || !Number.isFinite(rightTime) || Math.abs(leftTime - rightTime) > CORRELATION_MS) continue;
      const paired = (groupAddition(left) && adminCommand(right)) || (adminCommand(left) && groupAddition(right));
      if (!paired) continue;
      const leftDecision = outputs.find((item) => item.alert === left)?.decision;
      const rightDecision = outputs.find((item) => item.alert === right)?.decision;
      if (![leftDecision, rightDecision].some((decision) => decision?.action === "block" && decision.confidence >= 0.85)) continue;
      if (Number(left?.rule?.level) < 10 || Number(right?.rule?.level) < 10) continue;
      const techniques = [...(left?.rule?.mitre ?? []), ...(right?.rule?.mitre ?? [])];
      if (!techniques.some((id) => ["T1078", "T1068"].includes(id))) continue;
      createCandidate(candidates, leftSubject, [left.id, right.id],
        "recent_group_change_then_admin_command", 0.97);
    }
  }

  const rulesById = new Map(currentRules.map((rule) => [rule.id, rule]));
  for (const candidate of candidates.values()) {
    const safeSuffix = createHash("sha256").update(candidate.subjectId).digest("hex").slice(0, 16);
    const id = "xdr-privilege-" + safeSuffix;
    const rule = {
      id,
      effect: "deny",
      subjectId: candidate.subjectId,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
      evidenceAlertIds: candidate.evidenceAlertIds,
      evidencePattern: candidate.evidencePattern,
      confidence: candidate.confidence
    };
    rulesById.set(id, rule);
    logLines.push(JSON.stringify({
      at: now.toISOString(),
      moduleKey: "privilege",
      alertIds: candidate.evidenceAlertIds,
      action: "block",
      confidence: candidate.confidence,
      reason: "명확한 권한 상승 결합 사건으로 세션 거부 규칙 생성",
      ruleId: id,
      expiresAt: rule.expiresAt
    }));
  }

  await mkdir(dirname(SESSION_RULES_FILE), { recursive: true });
  await writeFile(SESSION_RULES_FILE, JSON.stringify({
    schema: "aleph.xdr.session-deny.v1",
    generatedAt: now.toISOString(),
    rules: [...rulesById.values()]
  }, null, 2) + "\n", "utf8");
  if (logLines.length) {
    await mkdir(dirname(LOG_FILE), { recursive: true });
    await appendFile(LOG_FILE, logLines.join("\n") + "\n", "utf8");
  }
  if (process.argv.includes("--persist")) {
    await persistRulesToDatabase([...rulesById.values()]);
  }

  console.log("privilege 시험 경보: " + fixture.alerts.length + "건");
  console.log("판정: block " + counts.block + ", alert " + counts.alert + ", record " + counts.record);
  console.log("계정 세션 거부 규칙 생성/갱신: " + candidates.size + "건; 현재 활성 규칙: " + rulesById.size + "건");
  console.log("alerts.log 추가: " + logLines.length + "줄");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error("privilege 대응 실패: " + oneLine(error?.message ?? "알 수 없는 오류"));
    process.exitCode = 1;
  });
}
