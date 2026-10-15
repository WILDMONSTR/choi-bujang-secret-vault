import memoRestore from '../../src/api-handlers/stage10-memo-restore.mjs';
import policyDiff from '../../src/api-handlers/stage10-policy-diff.mjs';
import policyRestore from '../../src/api-handlers/stage10-policy-restore.mjs';
import operationsStatus from '../../src/api-handlers/stage12-operations-status.mjs';
import decisionCheck from '../../src/api-handlers/stage12-decision-check.mjs';
import detectionCheck from '../../src/api-handlers/stage12-detection-check.mjs';
import { sendResourceError } from '../../src/resource-access.mjs';

const handlers = {
  'memo-restore': memoRestore,
  'policy-diff': policyDiff,
  'policy-restore': policyRestore,
  'operations-status': operationsStatus,
  'decision-check': decisionCheck,
  'detection-check': detectionCheck
};

export default async function handler(req, res) {
  const raw = req.query?.action;
  const action = Array.isArray(raw) ? raw.join('/') : typeof raw === 'string' ? raw : '';
  const selected = handlers[action];
  if (!selected) return sendResourceError(res, 404, 'NOT_FOUND');
  return selected(req, res);
}
