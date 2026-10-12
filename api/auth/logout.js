import config from '../../aleph.config.json' with { type: 'json' };
import { clearSessionCookies, isTrustedBrowserOrigin } from '../../src/session-cookies.mjs';

function sendError(response, status, code) {
  return response.status(status).json({ error: code });
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
  if (!isTrustedBrowserOrigin(request, config)) {
    return sendError(response, 403, 'ORIGIN_NOT_ALLOWED');
  }

  clearSessionCookies(response);
  return response.status(200).json({ ok: true });
}
