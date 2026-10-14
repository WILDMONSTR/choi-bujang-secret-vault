import register from '../../src/api-handlers/device-register.mjs';
import approve from '../../src/api-handlers/device-approve.mjs';
import approveSelf from '../../src/api-handlers/device-approve-self.mjs';
import status from '../../src/api-handlers/device-status.mjs';
import { sendResourceError } from '../../src/resource-access.mjs';

const handlers = {
  register,
  approve,
  'approve-self': approveSelf,
  status
};

export default async function handler(req, res) {
  const raw = req.query?.action;
  const action = Array.isArray(raw) ? raw.join('/') : typeof raw === 'string' ? raw : '';
  const selected = handlers[action];
  if (!selected) return sendResourceError(res, 404, 'NOT_FOUND');
  return selected(req, res);
}
