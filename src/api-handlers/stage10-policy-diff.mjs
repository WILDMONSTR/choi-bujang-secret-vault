import {
  loadPolicyRestoreContext,
  requireStage10TestOwner,
  stage10ErrorResponse,
} from '../stage10-recovery-api.mjs';
import { sendResourceError } from '../resource-access.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireStage10TestOwner(req, res);
  if (!auth) return;

  try {
    const context = await loadPolicyRestoreContext(auth.supabase);
    return res.status(200).json(context.preview);
  } catch (error) {
    return stage10ErrorResponse(res, error);
  }
}
