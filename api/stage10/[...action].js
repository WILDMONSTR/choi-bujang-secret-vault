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
  // Vercel does not reliably populate req.query.action for catch-all API routes.
  // Route by the actual pathname; query-string parameters must not select a handler.
  const pathname = new URL(req.url, 'https://internal.invalid').pathname;
  const action = pathname.startsWith('/api/stage10/')
    ? pathname.slice('/api/stage10/'.length) : '';
  const selected = Object.hasOwn(handlers, action) ? handlers[action] : null;
  if (!selected) return sendResourceError(res, 404, 'NOT_FOUND');
  return selected(req, res);
}
