import { verifyDeviceRequest } from './device-signature.mjs';

export async function requireApprovedDevice(req, res, auth) {
  const deviceId = req?.headers?.['x-app-device-id'];
  if (typeof deviceId !== 'string') {
    res.status(401).json({ error: 'DEVICE_SIGNATURE_REQUIRED' });
    return false;
  }

  const { supabase: db, identity } = auth ?? {};
  if (!db || typeof identity?.userId !== 'string') {
    res.status(401).json({ error: 'UNAUTHORIZED' });
    return false;
  }

  try {
    const { data: device, error } = await db.from('app_devices')
      .select('id,owner_id,public_jwk,status')
      .eq('id', deviceId)
      .eq('owner_id', identity.userId)
      .maybeSingle();

    if (error) {
      res.status(503).json({ error: 'DEVICE_REGISTRY_UNAVAILABLE' });
      return false;
    }
    if (!device || device.owner_id !== identity.userId) {
      res.status(403).json({ error: 'DEVICE_NOT_REGISTERED' });
      return false;
    }
    if (device.status !== 'approved') {
      res.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
      return false;
    }

    const checked = verifyDeviceRequest(req, device.public_jwk);
    if (!checked.valid || checked.deviceId !== device.id) {
      res.status(401).json({ error: checked.code || 'INVALID_DEVICE_SIGNATURE' });
      return false;
    }

    const signedAt = new Date(checked.timestamp).toISOString();
    const expiresAt = new Date(checked.timestamp + 120_000).toISOString();
    const { error: nonceError } = await db.from('app_device_request_nonces').insert({
      device_id: device.id,
      nonce: checked.nonce,
      signed_at: signedAt,
      expires_at: expiresAt
    });
    if (nonceError) {
      res.status(nonceError.code === '23505' ? 409 : 503).json({
        error: nonceError.code === '23505' ? 'DEVICE_REQUEST_REPLAYED' : 'DEVICE_REPLAY_CHECK_UNAVAILABLE'
      });
      return false;
    }

    await db.from('app_devices').update({ last_seen_at: new Date().toISOString() })
      .eq('id', device.id).eq('owner_id', identity.userId).eq('status', 'approved');

    // Expired replay records are safe to remove; live nonces remain protected by the primary key.
    await db.from('app_device_request_nonces').delete()
      .lt('expires_at', new Date().toISOString());

    return true;
  } catch {
    res.status(503).json({ error: 'DEVICE_VERIFICATION_UNAVAILABLE' });
    return false;
  }
}
