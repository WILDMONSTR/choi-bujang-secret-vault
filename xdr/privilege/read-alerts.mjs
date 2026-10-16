import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, "../fixtures/privilege.json");
const REDACTED = "[REDACTED]";

function oneLine(value) {
  return typeof value === "string" ? value.replace(/[\r\n\t]+/g, " ").trim() : "";
}
function redactSecrets(value) {
  let text = oneLine(value);
  text = text
    .replace(/\b(password|passwd|pwd|token|secret|api[_ -]?key|authorization|client[_ -]?secret|access[_ -]?key|private[_ -]?key)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, "$1=[REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b/g, REDACTED)
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, REDACTED)
    .replace(/\b[A-Fa-f0-9]{32,}\b/g, REDACTED);
  return text;
}
function safeAddress(value) {
  const candidate = redactSecrets(value);
  return isIP(candidate) ? candidate : (candidate ? REDACTED : "");
}
function safeAccount(value) {
  const candidate = redactSecrets(value);
  if (!candidate || candidate === REDACTED || /(?:password|passwd|pwd|token|secret|api[_ -]?key|authorization)\s*[:=]/i.test(candidate)) {
    return REDACTED;
  }
  return candidate;
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE, "utf8"));
  if (fixture?.schema !== "aleph.xdr.fixture.v1" || fixture.moduleKey !== "privilege" || !Array.isArray(fixture.alerts)) {
    throw new Error("privilege 경보 fixture 형식이 올바르지 않습니다.");
  }

  for (const alert of fixture.alerts) {
    const output = {
      timestamp: redactSecrets(alert?.timestamp),
      sourceAddress: safeAddress(alert?.data?.srcip),
      account: safeAccount(alert?.data?.srcuser),
      ruleLevel: Number.isInteger(Number(alert?.rule?.level)) ? Number(alert.rule.level) : null,
      description: redactSecrets(alert?.rule?.description)
    };
    console.log(JSON.stringify(output));
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(() => {
    console.error("privilege 경보를 안전하게 읽지 못했습니다.");
    process.exitCode = 1;
  });
}
