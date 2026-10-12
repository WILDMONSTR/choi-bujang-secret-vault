import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const NOTE_TITLES = Object.freeze([
  '과제',
  '포트폴리오',
  '아침 리추얼',
  '훈련 행정 자료',
]);

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
        || parsedUrl.pathname !== '/' || parsedUrl.search || parsedUrl.hash) {
      return null;
    }
    return parsedUrl.origin;
  } catch {
    return null;
  }
}

function getContext(supabaseUrl, secretKey) {
  if (cachedContext?.supabaseUrl === supabaseUrl
      && cachedContext?.secretKey === secretKey) {
    return cachedContext;
  }

  const supabase = createClient(supabaseUrl, secretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
  const verifyLogin = createLoginVerifier({
    config,
    supabaseSecretKey: secretKey,
    supabaseClient: supabase,
  });

  cachedContext = { supabaseUrl, secretKey, supabase, verifyLogin };
  return cachedContext;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return sendError(response, 405, 'METHOD_NOT_ALLOWED');
  }

  // Trust only a server-verified Authorization bearer token. Never read userId
  // or role from the request body, query string, or other browser-controlled data.
  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return sendError(response, 401, 'UNAUTHORIZED');
  }

  const configuredUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  const supabaseUrl = validSupabaseUrl(configuredUrl);
  const configuredIssuer = config?.identityProvider?.issuer;
  let issuerOrigin;
  try {
    issuerOrigin = new URL(configuredIssuer).origin;
  } catch {
    return sendError(response, 503, 'AUTH_NOT_CONFIGURED');
  }

  if (!supabaseUrl || !secretKey || !secretKey.trim()
      || secretKey !== secretKey.trim() || supabaseUrl !== issuerOrigin) {
    return sendError(response, 503, 'NOT_CONFIGURED');
  }

  let context;
  try {
    context = getContext(supabaseUrl, secretKey);
  } catch {
    return sendError(response, 503, 'AUTH_NOT_CONFIGURED');
  }

  let identity;
  try {
    identity = await context.verifyLogin(authorization);
  } catch {
    // Verification exceptions fail closed and do not expose internal details.
    return sendError(response, 401, 'UNAUTHORIZED');
  }
  // This endpoint is for regular Supabase Auth accounts, not judge identities.
  // Never trust request-supplied user IDs or roles.
  if (!identity || identity.kind !== 'student') {
    return sendError(response, 401, 'UNAUTHORIZED');
  }

  try {
    const { data, error } = await context.supabase
      .from('learning_notes')
      .select('title, content');

    if (error || !Array.isArray(data)) {
      return sendError(response, 502, 'NOTES_UNAVAILABLE');
    }

    const notesByTitle = new Map();
    for (const row of data) {
      if (!row || !NOTE_TITLES.includes(row.title)
          || typeof row.content !== 'string') {
        continue;
      }
      if (notesByTitle.has(row.title)) {
        return sendError(response, 502, 'NOTES_UNAVAILABLE');
      }
      notesByTitle.set(row.title, { title: row.title, content: row.content });
    }

    const notes = NOTE_TITLES.map(title => notesByTitle.get(title));
    if (notes.some(note => !note)) {
      return sendError(response, 502, 'NOTES_UNAVAILABLE');
    }

    // Return only intended virtual notes. Never include tokens, secrets, or raw errors.
    return response.status(200).json({ notes });
  } catch {
    // Do not log Supabase exceptions; they may contain sensitive details.
    return sendError(response, 502, 'NOTES_UNAVAILABLE');
  }
}
