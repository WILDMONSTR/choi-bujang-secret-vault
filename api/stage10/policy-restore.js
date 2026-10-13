import {
  loadPolicyRestoreContext,
  requireStage10TestOwner,
  stage10ErrorResponse,
  validPolicyConfirmation,
} from '../../src/stage10-recovery-api.mjs';
import { hashJson, policyService } from '../../src/stage10-recovery.mjs';
import { sendResourceError } from '../../src/resource-access.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireStage10TestOwner(req, res);
  if (!auth) return;

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = null; }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || body.confirm !== true || typeof body.snapshotId !== 'string'
      || typeof body.restoreVersion !== 'string' || typeof body.snapshotSha256 !== 'string'
      || typeof body.currentSha256 !== 'string' || typeof body.currentUpdatedAt !== 'string') {
    return sendResourceError(res, 400, 'CONFIRMATION_REQUIRED');
  }

  try {
    const context = await loadPolicyRestoreContext(auth.supabase);
    if (!validPolicyConfirmation(body, context)) {
      return sendResourceError(res, 409, 'PREVIEW_STALE');
    }
    if (context.preview.truncated) {
      return sendResourceError(res, 409, 'DIFF_TOO_LARGE_FOR_PREVIEW');
    }
    if (!context.preview.canRestore) {
      return sendResourceError(res, 409, 'NO_POLICY_CHANGES');
    }

    const { data, error } = await auth.supabase.rpc('stage10_restore_test_policy', {
      p_snapshot_id: context.copy.snapshot_id,
      p_expected_version: context.copy.version,
      p_expected_sha256: context.copy.sha256,
      p_expected_updated_at: context.current.updated_at,
      p_target_service_policy: policyService(context.copy.policy_json),
      p_actor_id: auth.identity.userId,
      p_before_sha256: context.preview.currentServiceSha256,
      p_after_sha256: hashJson(policyService(context.copy.policy_json)),
    });
    if (error) {
      const message = String(error.message ?? '');
      if (message.includes('POLICY_CHANGED_SINCE_PREVIEW')) {
        return sendResourceError(res, 409, 'PREVIEW_STALE');
      }
      if (message.includes('SAFE_POLICY_COPY')) {
        return sendResourceError(res, 409, 'SAFE_POLICY_COPY_INVALID');
      }
      if (message.includes('TEST_POLICY_UNAVAILABLE')) {
        return sendResourceError(res, 409, 'TEST_POLICY_UNAVAILABLE');
      }
      return sendResourceError(res, 502, 'POLICY_RESTORE_FAILED');
    }
    if (!data || typeof data.auditId !== 'string'
        || data.version !== context.copy.version) {
      return sendResourceError(res, 502, 'POLICY_RESTORE_FAILED');
    }

    const preservedServices = Object.keys(context.current.policy_json.services)
      .filter((key) => key !== 'learning_notes').sort();
    return res.status(200).json({
      restored: true,
      testOnly: true,
      policyKey: 'learning_notes',
      restoreVersion: context.copy.version,
      restoredScope: 'services.learning_notes',
      changedFields: context.preview.changeCount,
      preservedServices,
      auditId: data.auditId,
      updatedAt: data.updatedAt,
    });
  } catch (error) {
    return stage10ErrorResponse(res, error);
  }
}
