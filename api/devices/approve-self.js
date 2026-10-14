import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../../src/resource-access.mjs';
import { validatePublicJwk } from '../../src/device-signature.mjs';

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
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (!body || typeof deviceId !== 'string' || !UUID.test(deviceId)
      || !email || email.length > 320 || !password || password.length > 1024) {
    return sendResourceError(res, 400, 'INVALID_DEVICE_APPROVAL');
  }

  const url = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!url || !publishableKey || publishableKey !== publishableKey.trim()) {
    return sendResourceError(res, 503, 'DEVICE_APPROVAL_NOT_CONFIGURED');
  }

  try {
    const reauthClient = createClient(url, publishableKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
    });
    const { data: signedIn, error: signInError } = await reauthClient.auth.signInWithPassword({ email, password });
    if (signInError || signedIn?.user?.id !== auth.identity.userId) {
      return sendResourceError(res, 403, 'PASSWORD_REAUTH_FAILED');
    }

    const db = auth.supabase;
    const { data: device, error: lookupError } = await db.from('app_devices')
      .select('id,owner_id,status').eq('id', deviceId)
      .eq('owner_id', auth.identity.userId).maybeSingle();
    if (lookupError) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    if (!device) return sendResourceError(res, 404, 'DEVICE_NOT_FOUND');
    if (device.status === 'approved') return res.status(200).json({ deviceId, status: 'approved' });
    if (device.status !== 'pending') return sendResourceError(res, 409, 'DEVICE_NOT_PENDING');

    const { data, error } = await db.from('app_devices').update({
      status: 'approved', approved_at: new Date().toISOString(),
      approved_by: auth.identity.userId
    }).eq('id', deviceId).eq('owner_id', auth.identity.userId)
      .eq('status', 'pending').select('id,status,approved_at').maybeSingle();
    if (error) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    if (!data) return sendResourceError(res, 409, 'DEVICE_NOT_PENDING');
    return res.status(200).json({ deviceId: data.id, status: data.status, approvedAt: data.approved_at });
  } catch {
    return sendResourceError(res, 503, 'DEVICE_APPROVAL_UNAVAILABLE');
  }
}
