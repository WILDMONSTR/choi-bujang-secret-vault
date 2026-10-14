import { matchesDeviceToken, readDeviceCredential } from './device-cookie.mjs';

export async function findDeviceForSession(req, auth) {
  const credential = readDeviceCredential(req);
  if (!credential) return { device: null, code: 'DEVICE_NOT_REGISTERED' };

  const { supabase: db, identity } = auth ?? {};
  if (!db || typeof identity?.userId !== 'string') {
    return { device: null, code: 'UNAUTHORIZED' };
  }

  const { data: device, error } = await db.from('app_devices')
    .select('id,owner_id,status,device_cookie_sha256,label,created_at,approved_at,last_seen_at')
    .eq('id', credential.deviceId)
    .eq('owner_id', identity.userId)
    .maybeSingle();

  if (error) return { device: null, code: 'DEVICE_REGISTRY_UNAVAILABLE' };
  if (!device || !matchesDeviceToken(credential.token, device.device_cookie_sha256)) {
    return { device: null, code: 'DEVICE_COOKIE_INVALID' };
  }
  return { device, code: null };
}

export async function requireApprovedDevice(req, res, auth) {
  try {
    const result = await findDeviceForSession(req, auth);
    if (result.code === 'DEVICE_REGISTRY_UNAVAILABLE') {
      res.status(503).json({ error: result.code });
      return false;
    }
    if (result.code === 'UNAUTHORIZED') {
      res.status(401).json({ error: result.code });
      return false;
    }
    if (!result.device) {
      res.status(403).json({ error: 'DEVICE_NOT_REGISTERED' });
      return false;
    }
    if (result.device.status !== 'approved') {
      res.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
      return false;
    }

    const { error: seenError } = await auth.supabase.from('app_devices')
      .update({ last_seen_at: new Date().toISOString() })
      .eq('id', result.device.id)
      .eq('owner_id', auth.identity.userId)
      .eq('status', 'approved');
    if (seenError) {
      res.status(503).json({ error: 'DEVICE_REGISTRY_UNAVAILABLE' });
      return false;
    }
    return true;
  } catch {
    res.status(503).json({ error: 'DEVICE_VERIFICATION_UNAVAILABLE' });
    return false;
  }
}
