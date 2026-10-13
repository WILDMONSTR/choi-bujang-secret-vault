import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const SCOPE = 'services.learning_notes';
const SENSITIVE_PATH = /(?:token|secret|password|private.?key|real.?name|email|memo.?body|content)/iu;

export class Stage10Error extends Error {
  constructor(status, code) {
    super(code);
    this.name = 'Stage10Error';
    this.status = status;
    this.code = code;
  }
}

function fail(status, code) {
  throw new Stage10Error(status, code);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  if (isRecord(value)) {
    return '{' + Object.keys(value).sort()
      .map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) fail(400, 'POLICY_VALUE_INVALID');
  return encoded;
}

export function hashJson(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

export function hashText(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function policyService(policy) {
  if (!isRecord(policy) || !isRecord(policy.services)
      || !isRecord(policy.services.learning_notes)) {
    fail(409, 'SAFE_POLICY_COPY_INVALID');
  }
  return policy.services.learning_notes;
}

function validTimestamp(value) {
  if (typeof value !== 'string' || !value.trim()) return NaN;
  return Date.parse(value);
}

export function validateSafePolicyCopy(copy, {
  expectedVersion,
  expectedSha256,
  now = new Date(),
} = {}) {
  if (!copy) fail(409, 'SAFE_POLICY_COPY_UNAVAILABLE');
  if (copy.policy_key !== 'learning_notes'
      || typeof copy.version !== 'string' || !copy.version.trim()
      || (expectedVersion && copy.version !== expectedVersion)
      || !UUID.test(String(copy.snapshot_id ?? ''))
      || copy.validated !== true
      || typeof copy.sha256 !== 'string' || !SHA256.test(copy.sha256)
      || !SHA256.test(String(expectedSha256 ?? ''))
      || copy.sha256 !== expectedSha256.toLowerCase()) {
    fail(409, 'SAFE_POLICY_COPY_INVALID');
  }

  const capturedAt = validTimestamp(copy.captured_at);
  const validatedAt = validTimestamp(copy.validated_at);
  const incidentAt = validTimestamp(copy.incident_at);
  if (!Number.isFinite(capturedAt) || !Number.isFinite(validatedAt)
      || !Number.isFinite(incidentAt) || capturedAt >= incidentAt
      || validatedAt >= incidentAt || incidentAt > now.getTime()) {
    fail(409, 'SAFE_POLICY_COPY_INVALID');
  }

  policyService(copy.policy_json);
  if (hashJson(copy.policy_json) !== copy.sha256) {
    fail(409, 'SAFE_POLICY_COPY_INVALID');
  }
  return copy;
}

function safeDisplayValue(path, value) {
  if (SENSITIVE_PATH.test(path)) return '[redacted]';
  if (typeof value === 'string' && value.length > 240) {
    return value.slice(0, 240) + '…';
  }
  return value;
}

function collectDiff(before, after, path, changes, limit) {
  if (canonicalJson(before) === canonicalJson(after)) return;
  if (isRecord(before) && isRecord(after)) {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    for (const key of keys) {
      if (changes.length >= limit) return;
      const hasBefore = Object.hasOwn(before, key);
      const hasAfter = Object.hasOwn(after, key);
      const childPath = path + '.' + key;
      if (hasBefore && hasAfter) {
        collectDiff(before[key], after[key], childPath, changes, limit);
      } else {
        changes.push({
          path: childPath,
          beforePresent: hasBefore,
          afterPresent: hasAfter,
          before: hasBefore ? safeDisplayValue(childPath, before[key]) : null,
          after: hasAfter ? safeDisplayValue(childPath, after[key]) : null,
        });
      }
    }
    return;
  }
  if (Array.isArray(before) && Array.isArray(after)) {
    const length = Math.max(before.length, after.length);
    for (let index = 0; index < length; index += 1) {
      if (changes.length >= limit) return;
      const hasBefore = index < before.length;
      const hasAfter = index < after.length;
      const childPath = path + '.' + index;
      if (hasBefore && hasAfter) {
        collectDiff(before[index], after[index], childPath, changes, limit);
      } else {
        changes.push({
          path: childPath,
          beforePresent: hasBefore,
          afterPresent: hasAfter,
          before: hasBefore ? safeDisplayValue(childPath, before[index]) : null,
          after: hasAfter ? safeDisplayValue(childPath, after[index]) : null,
        });
      }
    }
    return;
  }
  changes.push({
    path,
    beforePresent: true,
    afterPresent: true,
    before: safeDisplayValue(path, before),
    after: safeDisplayValue(path, after),
  });
}

export function diffPolicyScope(safePolicy, currentPolicy) {
  const before = policyService(safePolicy);
  const after = policyService(currentPolicy);
  const changes = [];
  collectDiff(before, after, SCOPE, changes, 100);
  return { changes, truncated: changes.length === 100 };
}

export function restorePolicyScope(currentPolicy, safePolicy) {
  const safeService = policyService(safePolicy);
  policyService(currentPolicy);
  const restored = structuredClone(currentPolicy);
  restored.services.learning_notes = structuredClone(safeService);
  return restored;
}

export function makePolicyPreview(copy, current) {
  if (!current || current.policy_key !== 'learning_notes'
      || typeof current.version !== 'string' || !current.version
      || typeof current.updated_at !== 'string'
      || !Number.isFinite(Date.parse(current.updated_at))) {
    fail(409, 'TEST_POLICY_UNAVAILABLE');
  }
  const result = diffPolicyScope(copy.policy_json, current.policy_json);
  return {
    testOnly: true,
    policyKey: 'learning_notes',
    scope: SCOPE,
    snapshotId: copy.snapshot_id,
    restoreVersion: copy.version,
    snapshotSha256: copy.sha256,
    currentVersion: current.version,
    currentSha256: hashJson(current.policy_json),
    currentServiceSha256: hashJson(policyService(current.policy_json)),
    currentUpdatedAt: current.updated_at,
    changeCount: result.changes.length,
    changes: result.changes,
    truncated: result.truncated,
    canRestore: result.changes.length > 0 && !result.truncated,
  };
}

export function validateMemoBackup(backup, {
  expectedBackupId,
  noteId,
  ownerId,
  contentSha256,
  now = new Date(),
} = {}) {
  if (!backup) fail(409, 'MEMO_BACKUP_UNAVAILABLE');
  const expectedHash = String(contentSha256 ?? '').toLowerCase();
  const capturedAt = validTimestamp(backup.captured_at);
  const validatedAt = validTimestamp(backup.validated_at);
  const incidentAt = validTimestamp(backup.incident_at);
  if (!UUID.test(String(expectedBackupId ?? ''))
      || backup.backup_id !== expectedBackupId
      || !UUID.test(String(noteId ?? '')) || backup.note_id !== noteId
      || !UUID.test(String(ownerId ?? '')) || backup.owner_id !== ownerId
      || backup.validated !== true
      || typeof backup.title !== 'string' || !backup.title.trim()
      || typeof backup.content !== 'string' || !backup.content.trim()
      || backup.content.length > 20000
      || typeof backup.zone_id !== 'string'
      || !/^[a-z0-9][a-z0-9_-]{0,63}$/u.test(backup.zone_id)
      || !SHA256.test(expectedHash)
      || backup.content_sha256 !== expectedHash
      || hashText(backup.content) !== expectedHash
      || !Number.isFinite(capturedAt) || !Number.isFinite(validatedAt)
      || !Number.isFinite(incidentAt) || capturedAt >= incidentAt
      || validatedAt >= incidentAt || incidentAt > now.getTime()) {
    fail(409, 'MEMO_BACKUP_INVALID');
  }
  return {
    backupId: backup.backup_id,
    noteId: backup.note_id,
    ownerId: backup.owner_id,
    zoneId: backup.zone_id,
    contentSha256: expectedHash,
  };
}

export function isUuid(value) {
  return typeof value === 'string' && UUID.test(value);
}
