import assert from 'node:assert/strict';
import {
  diffPolicyScope,
  hashJson,
  hashText,
  makePolicyPreview,
  restorePolicyScope,
  validateMemoBackup,
  validateSafePolicyCopy,
} from '../src/stage10-recovery.mjs';

const now = new Date('2026-10-14T00:00:00.000Z');
const safePolicy = {
  version: 'safe-before-incident-v1',
  services: {
    learning_notes: {
      rules: [
        { id: 'deny-cross-owner', when: 'owner_mismatch', effect: 'deny' },
        { id: 'allow-owner', when: 'owner_match', effect: 'allow' },
      ],
    },
    announcements: { rules: [{ id: 'announcement-read', effect: 'allow' }] },
  },
  audit: [{ id: 'historical-event-1', action: 'preserve' }],
};
const copy = {
  snapshot_id: '11111111-1111-4111-8111-111111111111',
  policy_key: 'learning_notes',
  version: 'safe-before-incident-v1',
  policy_json: safePolicy,
  sha256: hashJson(safePolicy),
  validated: true,
  captured_at: '2026-10-09T00:00:00.000Z',
  validated_at: '2026-10-09T00:01:00.000Z',
  incident_at: '2026-10-10T00:00:00.000Z',
};
const currentPolicy = {
  version: 'compromised-test-v2',
  services: {
    learning_notes: {
      rules: [
        { id: 'deny-cross-owner', when: 'owner_mismatch', effect: 'allow' },
        { id: 'allow-owner', when: 'owner_match', effect: 'allow' },
      ],
    },
    announcements: { rules: [{ id: 'announcement-read', effect: 'allow' }] },
  },
  audit: [{ id: 'historical-event-1', action: 'preserve' }],
};
const current = {
  policy_key: 'learning_notes',
  version: 'compromised-test-v2',
  policy_json: currentPolicy,
  updated_at: '2026-10-11T00:00:00.000Z',
};

validateSafePolicyCopy(copy, {
  expectedVersion: copy.version,
  expectedSha256: copy.sha256,
  now,
});
process.stdout.write('통과 · 침해 이전에 검증된 사본과 SHA-256 일치 확인\n');

assert.throws(() => validateSafePolicyCopy(null, {
  expectedVersion: copy.version, expectedSha256: copy.sha256, now,
}), /SAFE_POLICY_COPY_UNAVAILABLE/u);
assert.throws(() => validateSafePolicyCopy({ ...copy, sha256: '0'.repeat(64) }, {
  expectedVersion: copy.version, expectedSha256: copy.sha256, now,
}), /SAFE_POLICY_COPY_INVALID/u);
assert.throws(() => validateSafePolicyCopy({
  ...copy, validated_at: '2026-10-10T00:00:00.000Z',
}, { expectedVersion: copy.version, expectedSha256: copy.sha256, now }), /SAFE_POLICY_COPY_INVALID/u);
process.stdout.write('통과 · 사본 누락·해시 불일치·침해 후 검증은 거부\n');

const diff = diffPolicyScope(copy.policy_json, current.policy_json);
assert.equal(diff.changes.length, 1);
assert.equal(diff.changes[0].path, 'services.learning_notes.rules.0.effect');
assert.equal(diff.changes[0].before, 'deny');
assert.equal(diff.changes[0].after, 'allow');
process.stdout.write('통과 · 차이 결과는 learning_notes의 변경 항목만 표시\n');

const preview = makePolicyPreview(copy, current);
assert.equal(preview.canRestore, true);
assert.equal(preview.restoreVersion, copy.version);
assert.equal(preview.currentSha256, hashJson(currentPolicy));
const restored = restorePolicyScope(currentPolicy, copy.policy_json);
assert.equal(restored.services.learning_notes.rules[0].effect, 'deny');
assert.deepEqual(restored.services.announcements, currentPolicy.services.announcements);
assert.deepEqual(restored.audit, currentPolicy.audit);
assert.equal(currentPolicy.services.learning_notes.rules[0].effect, 'allow');
process.stdout.write('통과 · 시험 정책의 지정 범위만 복원하고 다른 서비스·감사 이력 보존\n');

const memoContent = '가상 시험 메모 B - 복구 시험용';
const memo = {
  backup_id: '22222222-2222-4222-8222-222222222222',
  note_id: '33333333-3333-4333-8333-333333333333',
  owner_id: '44444444-4444-4444-8444-444444444444',
  zone_id: 'personal',
  title: '가상 메모 B',
  content: memoContent,
  content_sha256: hashText(memoContent),
  validated: true,
  captured_at: '2026-10-09T00:00:00.000Z',
  validated_at: '2026-10-09T00:01:00.000Z',
  incident_at: '2026-10-10T00:00:00.000Z',
};
const checked = validateMemoBackup(memo, {
  expectedBackupId: memo.backup_id,
  noteId: memo.note_id,
  ownerId: memo.owner_id,
  contentSha256: memo.content_sha256,
  now,
});
assert.equal(checked.noteId, memo.note_id);
assert.equal(checked.ownerId, memo.owner_id);
assert.equal(checked.contentSha256, memo.content_sha256);
assert.throws(() => validateMemoBackup(memo, {
  expectedBackupId: memo.backup_id,
  noteId: memo.note_id,
  ownerId: '55555555-5555-4555-8555-555555555555',
  contentSha256: memo.content_sha256,
  now,
}), /MEMO_BACKUP_INVALID/u);
assert.throws(() => validateMemoBackup(memo, {
  expectedBackupId: memo.backup_id,
  noteId: memo.note_id,
  ownerId: memo.owner_id,
  contentSha256: '0'.repeat(64),
  now,
}), /MEMO_BACKUP_INVALID/u);
process.stdout.write('통과 · 가상 메모는 지정 ID·소유자·본문 SHA-256 일치가 모두 필요\n');
process.stdout.write('전체 stage10 복구 단위 시험 통과. 실제 DB·배포 복구를 실행한 결과는 아닙니다.\n');
