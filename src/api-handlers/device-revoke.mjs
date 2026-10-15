import config from '../../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../resource-access.mjs';
import { requireApprovedDevice } from '../require-approved-device.mjs';
import { readDeviceCredential } from '../device-cookie.mjs';

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

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = null; }
  }
  const deviceId = body && typeof body === 'object' && !Array.isArray(body)
    ? body.deviceId : null;
  if (typeof deviceId !== 'string' || !UUID.test(deviceId)) {
    return sendResourceError(res, 400, 'INVALID_DEVICE_ID');
  }

  // The current credential is parsed from the HttpOnly cookie and already
  // verified against the server registry by requireApprovedDevice.
  const current = readDeviceCredential(req);
  if (!current || current.deviceId === deviceId) {
    return sendResourceError(res, 409, 'CURRENT_DEVICE_REVOCATION_FORBIDDEN');
  }

  try {
    const { data, error } = await auth.supabase.rpc('stage12_revoke_device', {
      p_device_id: deviceId,
      p_owner_id: auth.identity.userId,
      p_actor_id: auth.identity.userId,
      p_current_device_id: current.deviceId,
    });
    if (error) {
      const message = String(error.message || '');
      if (message.includes('DEVICE_NOT_FOUND')) return sendResourceError(res, 404, 'DEVICE_NOT_FOUND');
      if (message.includes('DEVICE_ALREADY_REVOKED')) return sendResourceError(res, 409, 'DEVICE_ALREADY_REVOKED');
      if (message.includes('DEVICE_NOT_APPROVED')) return sendResourceError(res, 409, 'DEVICE_NOT_APPROVED');
      if (message.includes('DEVICE_REVOKE_CURRENT_FORBIDDEN')) {
        return sendResourceError(res, 409, 'CURRENT_DEVICE_REVOCATION_FORBIDDEN');
      }
      return sendResourceError(res, 503, 'DEVICE_REVOCATION_UNAVAILABLE');
    }
    if (!data || data.revoked !== true || data.deviceId !== deviceId
        || data.status !== 'revoked' || typeof data.revocationId !== 'string'
        || typeof data.revokedAt !== 'string') {
      return sendResourceError(res, 503, 'DEVICE_REVOCATION_UNAVAILABLE');
    }
    return res.status(200).json({
      revoked: true,
      deviceId: data.deviceId,
      status: data.status,
      revocationId: data.revocationId,
      revokedAt: data.revokedAt,
      source: 'public.app_devices + stage12_device_revocation_audit',
    });
  } catch {
    return sendResourceError(res, 503, 'DEVICE_REVOCATION_UNAVAILABLE');
  }
}
