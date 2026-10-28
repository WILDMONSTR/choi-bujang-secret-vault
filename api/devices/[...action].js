import register from '../../src/api-handlers/device-register.mjs';
import approve from '../../src/api-handlers/device-approve.mjs';
import approveSelf from '../../src/api-handlers/device-approve-self.mjs';
import status from '../../src/api-handlers/device-status.mjs';
import revoke from '../../src/api-handlers/device-revoke.mjs';
import { sendResourceError } from '../../src/resource-access.mjs';

const handlers = {
  register,
  approve,
  'approve-self': approveSelf,
  status,
  revoke
};

export default async function handler(req, res) {
  // Vercel does not reliably populate req.query.action for catch-all API routes.
  // Route by the actual pathname; query-string parameters must not select a handler.
  const pathname = new URL(req.url, 'https://internal.invalid').pathname;
  const action = pathname.startsWith('/api/devices/')
    ? pathname.slice('/api/devices/'.length) : '';
  const selected = Object.hasOwn(handlers, action) ? handlers[action] : null;
  if (!selected) return sendResourceError(res, 404, 'NOT_FOUND');
  return selected(req, res);
}
