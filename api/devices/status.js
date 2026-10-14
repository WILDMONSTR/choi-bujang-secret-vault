import config from '../../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../../src/resource-access.mjs';
import { clearDeviceCookie } from '../../src/device-cookie.mjs';
import { findDeviceForSession } from '../../src/require-approved-device.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;

  try {
    const result = await findDeviceForSession(req, auth);
    if (result.code === 'DEVICE_REGISTRY_UNAVAILABLE') {
      return sendResourceError(res, 503, result.code);
    }
    if (result.code === 'DEVICE_COOKIE_INVALID') clearDeviceCookie(res);
    if (!result.device) {
      return res.status(200).json({
        registered: false, approved: false, status: 'unregistered'
      });
    }
    return res.status(200).json({
      registered: true,
      approved: result.device.status === 'approved',
      status: result.device.status,
      deviceId: result.device.id,
      label: result.device.label
    });
  } catch {
    return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
  }
}
