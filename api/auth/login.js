import { getServerAuthContext, verifyStudentToken } from '../../src/server-auth.mjs';
import { isTrustedBrowserOrigin, setSessionCookies } from '../../src/session-cookies.mjs';

function sendError(response, status, code) {
  return response.status(status).json({ error: code });
}

function parseBody(body) {
  let value = body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('Pragma', 'no-cache');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return sendError(response, 405, 'METHOD_NOT_ALLOWED');
  }
  if (!isTrustedBrowserOrigin(request, (await import('../../aleph.config.json', { with: { type: 'json' } })).default)) {
    return sendError(response, 403, 'ORIGIN_NOT_ALLOWED');
  }

  const input = parseBody(request.body);
  if (!input || typeof input.email !== 'string' || !input.email.trim()
      || input.email.trim().length > 320 || typeof input.password !== 'string'
      || input.password.length < 1 || input.password.length > 1024) {
    return sendError(response, 400, 'INVALID_CREDENTIALS');
  }

  let context;
  try {
    context = getServerAuthContext();
  } catch {
    return sendError(response, 503, 'AUTH_NOT_CONFIGURED');
  }

  try {
    const { data, error } = await context.supabase.auth.signInWithPassword({
      email: input.email.trim(),
      password: input.password,
    });
    if (error || !data?.session || !data?.user?.id) {
      return sendError(response, 401, 'INVALID_CREDENTIALS');
    }

    const identity = await verifyStudentToken(context, data.session.access_token);
    if (!identity || identity.userId !== data.user.id) {
      return sendError(response, 401, 'INVALID_CREDENTIALS');
    }

    setSessionCookies(response, data.session);
    return response.status(200).json({
      user: { id: identity.userId, email: typeof data.user.email === 'string' ? data.user.email : null },
    });
  } catch {
    return sendError(response, 502, 'AUTH_UNAVAILABLE');
  }
}
