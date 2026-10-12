import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

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

function parseRequestBody(body) {
  let value = body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function parseNote(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (typeof value.title !== 'string' || !value.title.trim() || value.title.trim().length > 200
      || typeof value.body !== 'string' || !value.body.trim() || value.body.length > 20000) {
    return null;
  }
  return { title: value.title.trim(), body: value.body };
}

function publicNote(row) {
  return { id: row.id, title: row.title, body: row.content };
}

function sendDatabaseError(response, error) {
  if (error?.code === '23505') return sendError(response, 409, 'TITLE_ALREADY_EXISTS');
  return sendError(response, 502, 'NOTES_UNAVAILABLE');
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');

  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return sendError(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return sendError(response, 401, 'UNAUTHORIZED');
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

  try {
    if (request.method === 'GET') {
      // List only this verified account's memos.
      const { data, error } = await context.supabase
        .from('learning_notes')
        .select('id, title, content')
        .eq('owner_id', identity.userId)
        .order('created_at', { ascending: false });
      if (error || !Array.isArray(data)) return sendError(response, 502, 'NOTES_UNAVAILABLE');
      return response.status(200).json(data.map(publicNote));
    }

    const input = parseRequestBody(request.body);
    const note = parseNote(input);
    if (!note) return sendError(response, 400, 'INVALID_NOTE');
    let id;
    if (Object.prototype.hasOwnProperty.call(input, 'id')) {
      if (typeof input.id !== 'string' || !UUID.test(input.id)) {
        return sendError(response, 400, 'INVALID_ID');
      }
      id = input.id;
    } else {
      id = randomUUID();
    }

    const { data, error } = await context.supabase
      .from('learning_notes')
      .insert({
        id,
        owner_id: identity.userId,
        title: note.title,
        content: note.body,
      })
      .select('id')
      .single();

    if (error) return sendDatabaseError(response, error);
    if (!data?.id) return sendError(response, 502, 'NOTES_UNAVAILABLE');
    return response.status(201).json({ id: data.id });
  } catch {
    return sendError(response, 502, 'NOTES_UNAVAILABLE');
  }
}
