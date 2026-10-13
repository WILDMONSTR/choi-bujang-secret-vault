import config from '../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from './resource-access.mjs';
import {
  Stage10Error,
  hashJson,
  makePolicyPreview,
  policyService,
  validateSafePolicyCopy,
} from './stage10-recovery.mjs';

export async function requireStage10TestOwner(req, res) {
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return null;

  const ownerB = process.env.STAGE10_TEST_OWNER_B_ID;
  if (!ownerB || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(ownerB)) {
    sendResourceError(res, 503, 'RESTORE_NOT_CONFIGURED');
    return null;
  }
  if (auth.identity.userId.toLowerCase() !== ownerB.toLowerCase()) {
    sendResourceError(res, 403, 'TEST_ACCOUNT_B_REQUIRED');
    return null;
  }
  return auth;
}

export async function loadPolicyRestoreContext(db) {
  const version = process.env.STAGE10_SAFE_POLICY_VERSION;
  const trustedHash = process.env.STAGE10_SAFE_POLICY_SHA256?.toLowerCase();
  if (typeof version !== 'string' || !version.trim()
      || typeof trustedHash !== 'string' || !/^[0-9a-f]{64}$/u.test(trustedHash)) {
    throw new Stage10Error(503, 'RESTORE_NOT_CONFIGURED');
  }

  const { data: copy, error: copyError } = await db.from('stage10_safe_policy_copies')
    .select('snapshot_id,policy_key,version,policy_json,sha256,validated,captured_at,validated_at,incident_at')
    .eq('policy_key', 'learning_notes').eq('version', version).maybeSingle();
  if (copyError) throw new Stage10Error(503, 'RESTORE_STORAGE_UNAVAILABLE');
  if (!copy) throw new Stage10Error(409, 'SAFE_POLICY_COPY_UNAVAILABLE');

  validateSafePolicyCopy(copy, { expectedVersion: version, expectedSha256: trustedHash });

  const { data: current, error: currentError } = await db.from('stage10_test_policies')
    .select('policy_key,version,policy_json,updated_at')
    .eq('policy_key', 'learning_notes').maybeSingle();
  if (currentError) throw new Stage10Error(503, 'RESTORE_STORAGE_UNAVAILABLE');
  if (!current) throw new Stage10Error(409, 'TEST_POLICY_UNAVAILABLE');

  policyService(current.policy_json);
  const preview = makePolicyPreview(copy, current);
  return { copy, current, preview };
}

export function stage10ErrorResponse(res, error) {
  if (error instanceof Stage10Error) {
    return res.status(error.status).json({ error: error.code });
  }
  return res.status(502).json({ error: 'RESTORE_FAILED' });
}

export function validPolicyConfirmation(body, context) {
  return body?.confirm === true
    && body.snapshotId === context.preview.snapshotId
    && body.restoreVersion === context.preview.restoreVersion
    && body.snapshotSha256 === context.preview.snapshotSha256
    && body.currentSha256 === context.preview.currentSha256
    && body.currentUpdatedAt === context.preview.currentUpdatedAt
    && hashJson(context.current.policy_json) === body.currentSha256;
}

export function restoredService(policy) {
  return policyService(policy);
}
