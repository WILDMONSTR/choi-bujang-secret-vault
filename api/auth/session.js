import config from '../../aleph.config.json' with { type: 'json' };
import { createIsolatedAuthClient, getServerAuthContext, verifyStudentToken } from '../../src/server-auth.mjs';
import { clearSessionCookies, readSessionCookies, setSessionCookies } from '../../src/session-cookies.mjs';

function sendError(response, status, code) {
  return response.status(status).json({ error: code });
}

async function userForToken(context, authClient, token) {
  const identity = await verifyStudentToken(context, token);
  if (!identity) return null;
  let email = null;
  try {
    const { data, error } = await authClient.auth.getUser(token);
    if (!error && data?.user?.id === identity.userId
        && typeof data.user.email === 'string') email = data.user.email;
  } catch {
    // The verified subject remains safe to return; email is optional display data.
  }
  return { user: { id: identity.userId, email } };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('Pragma', 'no-cache');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return sendError(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const tokens = readSessionCookies(request);
  if (!tokens.accessToken && !tokens.refreshToken) {
    return response.status(200).json({ user: null });
  }

  let context;
  try {
    context = getServerAuthContext();
  } catch {
    return sendError(response, 503, 'AUTH_NOT_CONFIGURED');
  }

  try {
    const authClient = createIsolatedAuthClient(context);
    if (tokens.accessToken) {
      const currentUser = await userForToken(context, authClient, tokens.accessToken);
      if (currentUser) return response.status(200).json(currentUser);
    }

    if (!tokens.refreshToken) {
      clearSessionCookies(response);
      return response.status(200).json({ user: null });
    }

    const { data, error } = await authClient.auth.refreshSession({
      refresh_token: tokens.refreshToken,
    });
    if (error || !data?.session || !data?.user?.id) {
      clearSessionCookies(response);
      return response.status(200).json({ user: null });
    }

    const identity = await verifyStudentToken(context, data.session.access_token);
    if (!identity || identity.userId !== data.user.id) {
      clearSessionCookies(response);
      return response.status(200).json({ user: null });
    }

    setSessionCookies(response, data.session);
    return response.status(200).json({
      user: { id: identity.userId, email: typeof data.user.email === 'string' ? data.user.email : null },
    });
  } catch {
    return sendError(response, 502, 'AUTH_UNAVAILABLE');
  }
}
