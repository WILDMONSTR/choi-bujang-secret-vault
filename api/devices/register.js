import config from '../../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../../src/resource-access.mjs';
import { publicKeyFingerprint, validatePublicJwk } from '../../src/device-signature.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;

  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : null;
  const deviceId = body?.deviceId;
  const label = typeof body?.label === 'string' ? body.label.trim() : '이 기기';
  const publicJwk = validatePublicJwk(body?.publicJwk);
  if (!body || typeof deviceId !== 'string' || !UUID.test(deviceId)
      || !publicJwk || !label || label.length > 80) {
    return sendResourceError(res, 400, 'INVALID_DEVICE_REGISTRATION');
  }

  try {
    const fingerprint = publicKeyFingerprint(publicJwk);
    const db = auth.supabase;
    const { data: sameId, error: idError } = await db.from('app_devices')
      .select('id,owner_id,public_key_sha256,status,label')
      .eq('id', deviceId).maybeSingle();
    if (idError) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    if (sameId) {
      if (sameId.owner_id !== auth.identity.userId || sameId.public_key_sha256 !== fingerprint) {
        return sendResourceError(res, 409, 'DEVICE_ID_CONFLICT');
      }
      return res.status(200).json({
        deviceId: sameId.id, status: sameId.status, label: sameId.label,
        fingerprint: fingerprint.slice(0, 16)
      });
    }

    const { data: existingKey, error: keyError } = await db.from('app_devices')
      .select('id,owner_id,status,label')
      .eq('owner_id', auth.identity.userId).eq('public_key_sha256', fingerprint).maybeSingle();
    if (keyError) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    if (existingKey) {
      return res.status(200).json({
        deviceId: existingKey.id, status: existingKey.status, label: existingKey.label,
        fingerprint: fingerprint.slice(0, 16)
      });
    }

    const { data, error } = await db.from('app_devices').insert({
      id: deviceId,
      owner_id: auth.identity.userId,
      public_jwk: publicJwk,
      public_key_sha256: fingerprint,
      label,
      status: 'pending'
    }).select('id,status,label,public_key_sha256').single();

    if (error || !data) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    return res.status(201).json({
      deviceId: data.id, status: data.status, label: data.label,
      fingerprint: data.public_key_sha256.slice(0, 16)
    });
  } catch {
    return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
  }
}
