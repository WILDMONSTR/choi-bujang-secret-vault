import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { isTrustedBrowserOrigin, readSessionCookies } from '../../src/session-cookies.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
let cachedContext = null;

function sendError(response, status, code) {
  return response.status(status).json({ error: code });
}

function validSupabaseUrl(value) {
  if (typeof value !== 'string' || !value.trim() || value !== value.trim()) return null;
  try {
    const parsedUrl = new URL(value);
    if (parsedUrl.protocol !== 'https:' || !parsedUrl.hostname
        || parsedUrl.username || parsedUrl.password
        || parsedUrl.pathname !== '/' || parsedUrl.search || parsedUrl.hash) return null;
    return parsedUrl.origin;
  } catch {
    return null;
  }
}

function getContext(supabaseUrl, secretKey) {
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

function parseNote(body) {
  let value = body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || typeof value.title !== 'string' || !value.title.trim()
      || value.title.trim().length > 200 || typeof value.body !== 'string'
      || !value.body.trim() || value.body.length > 20000) return null;
  return { title: value.title.trim(), body: value.body };
}

function publicNote(row) {
  return { id: row.id, title: row.title, body: row.content };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');

  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return sendError(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const suppliedAuthorization = request.headers?.authorization;
  let authorization = suppliedAuthorization;
  let usingCookie = false;
  if (typeof suppliedAuthorization !== 'string' || !suppliedAuthorization) {
    const cookies = readSessionCookies(request);
    if (cookies.accessToken) {
      authorization = 'Bearer ' + cookies.accessToken;
      usingCookie = true;
    }
  }
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return sendError(response, 401, 'UNAUTHORIZED');
  }
  if (usingCookie && request.method !== 'GET' && !isTrustedBrowserOrigin(request, config)) {
    return sendError(response, 403, 'ORIGIN_NOT_ALLOWED');
  }

  const supabaseUrl = validSupabaseUrl(process.env.SUPABASE_URL);
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  let issuerOrigin;
  try { issuerOrigin = new URL(config?.identityProvider?.issuer).origin; } catch {
    return sendError(response, 503, 'AUTH_NOT_CONFIGURED');
  }
  if (!supabaseUrl || !secretKey || !secretKey.trim()
      || secretKey !== secretKey.trim() || supabaseUrl !== issuerOrigin) {
    return sendError(response, 503, 'NOT_CONFIGURED');
  }

  let context;
  try { context = getContext(supabaseUrl, secretKey); } catch {
    return sendError(response, 503, 'AUTH_NOT_CONFIGURED');
  }

  let identity;
  try { identity = await context.verifyLogin(authorization); } catch {
    return sendError(response, 401, 'UNAUTHORIZED');
  }
  if (!identity || identity.kind !== 'student' || !UUID.test(identity.userId ?? '')) {
    return sendError(response, 401, 'UNAUTHORIZED');
  }

  const id = request.query?.id;
  if (typeof id !== 'string' || !UUID.test(id)) return sendError(response, 400, 'INVALID_ID');

  try {
    if (request.method === 'GET') {
      // Return a row only when it belongs to the verified user; hide other users' rows as not found.
      const { data, error } = await context.supabase
        .from('learning_notes')
        .select('id, title, content')
        .eq('id', id)
        .eq('owner_id', identity.userId)
        .maybeSingle();
      if (error) return sendError(response, 502, 'NOTES_UNAVAILABLE');
      if (!data) return sendError(response, 404, 'NOT_FOUND');
      return response.status(200).json(publicNote(data));
    }

    if (request.method === 'PUT') {
      const note = parseNote(request.body);
      if (!note) return sendError(response, 400, 'INVALID_NOTE');

      // Access only a row owned by the verified user.
      const { data, error } = await context.supabase
        .from('learning_notes')
        .update({ title: note.title, content: note.body })
        .eq('id', id)
        .eq('owner_id', identity.userId)
        .select('id, title, content')
        .maybeSingle();

      if (error?.code === '23505') return sendError(response, 409, 'TITLE_ALREADY_EXISTS');
      if (error) return sendError(response, 502, 'NOTES_UNAVAILABLE');
      if (!data) return sendError(response, 404, 'NOT_FOUND');
      return response.status(200).json(publicNote(data));
    }

    // Access only a row owned by the verified user.
    const { data, error } = await context.supabase
      .from('learning_notes')
      .delete()
      .eq('id', id)
      .eq('owner_id', identity.userId)
      .select('id')
      .maybeSingle();

    if (error) return sendError(response, 502, 'NOTES_UNAVAILABLE');
    if (!data) return sendError(response, 404, 'NOT_FOUND');
    return response.status(204).end();
  } catch {
    return sendError(response, 502, 'NOTES_UNAVAILABLE');
  }
}
