import memoRestore from '../../src/api-handlers/stage10-memo-restore.mjs';
import policyDiff from '../../src/api-handlers/stage10-policy-diff.mjs';
import policyRestore from '../../src/api-handlers/stage10-policy-restore.mjs';
import { sendResourceError } from '../../src/resource-access.mjs';

const handlers = {
  'memo-restore': memoRestore,
  'policy-diff': policyDiff,
  'policy-restore': policyRestore
};

export default async function handler(req, res) {
  const raw = req.query?.action;
  const action = Array.isArray(raw) ? raw.join('/') : typeof raw === 'string' ? raw : '';
  const selected = handlers[action];
  if (!selected) return sendResourceError(res, 404, 'NOT_FOUND');
  return selected(req, res);
}
