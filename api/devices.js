import config from '../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../src/resource-access.mjs';
import { requireApprovedDevice } from '../src/require-approved-device.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;
  if (!await requireApprovedDevice(req, res, auth)) return;

  try {
    const { data, error } = await auth.supabase.from('app_devices')
      .select('id,label,status,created_at,approved_at,last_seen_at,public_key_sha256')
      .eq('owner_id', auth.identity.userId).order('created_at', { ascending: false });
    if (error || !Array.isArray(data)) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    return res.status(200).json(data.map((device) => ({
      deviceId: device.id, label: device.label, status: device.status,
      createdAt: device.created_at, approvedAt: device.approved_at,
      lastSeenAt: device.last_seen_at, fingerprint: device.public_key_sha256.slice(0, 16)
    })));
  } catch {
    return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
  }
}
