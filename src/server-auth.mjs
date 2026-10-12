import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
let cachedContext = null;

function validSupabaseUrl(value) {
  if (typeof value !== 'string' || !value.trim() || value !== value.trim()) return null;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password
        || parsed.pathname !== '/' || parsed.search || parsed.hash) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

export function getServerAuthContext() {
  const supabaseUrl = validSupabaseUrl(process.env.SUPABASE_URL);
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  let issuerOrigin;
  try {
    issuerOrigin = new URL(config?.identityProvider?.issuer).origin;
  } catch {
    throw new Error('AUTH_NOT_CONFIGURED');
  }

  if (!supabaseUrl || !secretKey || !secretKey.trim() || secretKey !== secretKey.trim()
      || supabaseUrl !== issuerOrigin) {
    throw new Error('AUTH_NOT_CONFIGURED');
  }

  if (cachedContext?.supabaseUrl === supabaseUrl && cachedContext?.secretKey === secretKey) {
    return cachedContext;
  }

  const supabase = createClient(supabaseUrl, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  const verifyLogin = createLoginVerifier({
    config, supabaseSecretKey: secretKey, supabaseClient: supabase,
  });
  cachedContext = { supabaseUrl, secretKey, supabase, verifyLogin };
  return cachedContext;
}

export function createIsolatedAuthClient(context) {
  return createClient(context.supabaseUrl, context.secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

export async function verifyStudentToken(context, token) {
  if (typeof token !== 'string' || !token || token.length > 8192) return null;
  const identity = await context.verifyLogin('Bearer ' + token);
  if (!identity || identity.kind !== 'student' || !UUID.test(identity.userId ?? '')) return null;
  return identity;
}

export function isUuid(value) {
  return typeof value === 'string' && UUID.test(value);
}
