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
const TTL_MS = 15 * 60 * 1000;
const CORRELATION_MS = 5 * 60 * 1000;

function oneLine(value) {
  return String(value ?? "").replace(/[\r\n\t]+/g, " ").trim();
}
function trustedSubject(alert) {
  const identity = alert?.identity;
  const id = oneLine(identity?.subjectId);
  return identity?.source === "trusted-directory" && /^[A-Za-z0-9._:-]{1,128}$/.test(id) ? id : "";
}
function normalizedAccount(alert) {
  return oneLine(alert?.data?.srcuser)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
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
    const value = decide(alert);
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

export async function checkPrivilegeSessionDeny(subjectId, at = new Date()) {
  const id = typeof subjectId === "string" ? subjectId.trim() : "";
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(id)) return null;
  const now = at instanceof Date ? at : new Date(at);
  return (await loadExistingRules(now)).find((rule) => rule.subjectId === id && rule.id.startsWith("xdr-privilege-")) ?? null;
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE, "utf8"));
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
      if (!normalizedAccount(left) || normalizedAccount(left) !== normalizedAccount(right)) continue;
      const leftTime = Date.parse(left.timestamp);
      const rightTime = Date.parse(right.timestamp);
      if (!Number.isFinite(leftTime) || !Number.isFinite(rightTime) || Math.abs(leftTime - rightTime) > CORRELATION_MS) continue;
      const paired = (groupAddition(left) && adminCommand(right)) || (adminCommand(left) && groupAddition(right));
      if (!paired) continue;
      const leftLevel = Number(left?.rule?.level);
      const rightLevel = Number(right?.rule?.level);
      if (!Number.isFinite(leftLevel) || leftLevel < 10 || !Number.isFinite(rightLevel) || rightLevel < 10) continue;
      const hasRelevantMitre = (alert) => Array.isArray(alert?.rule?.mitre)
        && alert.rule.mitre.some((id) => ["T1078", "T1068"].includes(id));
      if (!hasRelevantMitre(left) || !hasRelevantMitre(right)) continue;
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
