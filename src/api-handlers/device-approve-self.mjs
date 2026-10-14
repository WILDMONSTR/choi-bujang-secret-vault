import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../resource-access.mjs';
import { findDeviceForSession } from '../require-approved-device.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;

  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : null;
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (!body || !email || email.length > 320 || !password || password.length > 1024) {
    return sendResourceError(res, 400, 'INVALID_DEVICE_APPROVAL');
  }

  const current = await findDeviceForSession(req, auth);
  if (current.code === 'DEVICE_REGISTRY_UNAVAILABLE') {
    return sendResourceError(res, 503, current.code);
  }
  if (!current.device) return sendResourceError(res, 403, 'DEVICE_NOT_REGISTERED');
  if (current.device.status === 'revoked') return sendResourceError(res, 409, 'DEVICE_REVOKED');

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

    if (current.device.status === 'approved') {
      return res.status(200).json({ deviceId: current.device.id, status: 'approved' });
    }

    const { data, error } = await auth.supabase.from('app_devices').update({
      status: 'approved', approved_at: new Date().toISOString(),
      approved_by: auth.identity.userId
    }).eq('id', current.device.id).eq('owner_id', auth.identity.userId)
      .eq('status', 'pending').select('id,status,approved_at').maybeSingle();
    if (error) return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    if (!data) return sendResourceError(res, 409, 'DEVICE_NOT_PENDING');
    return res.status(200).json({ deviceId: data.id, status: data.status, approvedAt: data.approved_at });
  } catch {
    return sendResourceError(res, 503, 'DEVICE_APPROVAL_UNAVAILABLE');
  }
}
