import config from '../../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../../src/resource-access.mjs';
import { requireApprovedDevice } from '../../src/require-approved-device.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;
  if (!await requireApprovedDevice(req, res, auth)) return;

  const targetId = req.body?.deviceId;
  if (typeof targetId !== 'string' || !UUID.test(targetId)
      || targetId === req.headers['x-app-device-id']) {
    return sendResourceError(res, 400, 'INVALID_DEVICE_ID');
  }

  try {
    const db = auth.supabase;
    const { data: target, error: lookupError } = await db.from('app_devices')
      .select('id,owner_id,status')
      .eq('id', targetId).eq('owner_id', auth.identity.userId).maybeSingle();
    if (lookupError) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    if (!target) return sendResourceError(res, 404, 'DEVICE_NOT_FOUND');
    if (target.status !== 'pending') return sendResourceError(res, 409, 'DEVICE_NOT_PENDING');

    const { data, error } = await db.from('app_devices').update({
      status: 'approved', approved_at: new Date().toISOString(),
      approved_by: auth.identity.userId
    }).eq('id', targetId).eq('owner_id', auth.identity.userId)
      .eq('status', 'pending').select('id,status,approved_at').maybeSingle();
    if (error) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    if (!data) return sendResourceError(res, 409, 'DEVICE_NOT_PENDING');
    return res.status(200).json({ deviceId: data.id, status: data.status, approvedAt: data.approved_at });
  } catch {
    return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
  }
}
