import config from '../../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../resource-access.mjs';
import { clearDeviceCookie, createDeviceCredential, readDeviceCredential, setDeviceCookie } from '../device-cookie.mjs';
import { findDeviceForSession } from '../require-approved-device.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;

  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const suppliedLabel = typeof body.label === 'string' ? body.label.trim() : '이 브라우저';
  const label = suppliedLabel.slice(0, 80) || '이 브라우저';

  try {
    const current = await findDeviceForSession(req, auth);
    if (current.code === 'DEVICE_REGISTRY_UNAVAILABLE') {
      return sendResourceError(res, 503, current.code);
    }
    if (current.device) {
      return res.status(200).json({
        deviceId: current.device.id, status: current.device.status, label: current.device.label
      });
    }

    const oldCookie = readDeviceCredential(req);
    if (oldCookie) clearDeviceCookie(res);

    const credential = createDeviceCredential();
    const { data, error } = await auth.supabase.from('app_devices').insert({
      id: credential.deviceId,
      owner_id: auth.identity.userId,
      public_jwk: null,
      public_key_sha256: null,
      device_cookie_sha256: credential.tokenHash,
      label,
      status: 'pending'
    }).select('id,status,label').single();

    if (error || !data) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    setDeviceCookie(res, credential.deviceId, credential.token);
    return res.status(201).json({
      deviceId: data.id, status: data.status, label: data.label
    });
  } catch {
    return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
  }
}
