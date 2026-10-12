const ACCESS_COOKIE = 'bb_access';
const REFRESH_COOKIE = 'bb_refresh';
const ACCESS_MAX_AGE_SECONDS = 60 * 60;
const REFRESH_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
const COOKIE_VALUE = /^[A-Za-z0-9._~-]+$/u;

function safeCookieValue(value) {
  return typeof value === 'string' && value.length > 0
    && value.length <= 8192 && COOKIE_VALUE.test(value);
}

export function readSessionCookies(request) {
  const header = request?.headers?.cookie;
  const values = new Map();
  if (typeof header !== 'string' || header.length > 16384) {
    return { accessToken: null, refreshToken: null };
  }

  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    if (name !== ACCESS_COOKIE && name !== REFRESH_COOKIE) continue;
    if (values.has(name)) {
      values.set(name, null);
      continue;
    }
    values.set(name, part.slice(separator + 1).trim());
  }

  const access = values.get(ACCESS_COOKIE);
  const refresh = values.get(REFRESH_COOKIE);
  return {
    accessToken: safeCookieValue(access) ? access : null,
    refreshToken: safeCookieValue(refresh) ? refresh : null,
  };
}

export function setSessionCookies(response, session) {
  const accessToken = session?.access_token;
  const refreshToken = session?.refresh_token;
  if (!safeCookieValue(accessToken) || !safeCookieValue(refreshToken)) {
    throw new TypeError('invalid_session_tokens');
  }

  const reportedLifetime = Number(session.expires_in);
  const accessMaxAge = Number.isFinite(reportedLifetime)
    ? Math.max(0, Math.min(ACCESS_MAX_AGE_SECONDS, Math.floor(reportedLifetime)))
    : ACCESS_MAX_AGE_SECONDS;

  response.setHeader('Set-Cookie', [
    `${ACCESS_COOKIE}=${accessToken}; Path=/; Max-Age=${accessMaxAge}; HttpOnly; Secure; SameSite=Lax`,
    `${REFRESH_COOKIE}=${refreshToken}; Path=/; Max-Age=${REFRESH_MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
  ]);
}

export function clearSessionCookies(response) {
  response.setHeader('Set-Cookie', [
    `${ACCESS_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    `${REFRESH_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
  ]);
}

function hostFromOriginOrHost(value) {
  if (typeof value !== 'string' || !value.trim() || value !== value.trim()) return null;
  try {
    const input = value.includes('://') ? value : 'https://' + value;
    const parsed = new URL(input);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password
        || parsed.pathname !== '/' || parsed.search || parsed.hash) return null;
    return parsed.host.toLowerCase();
  } catch {
    return null;
  }
}

export function isTrustedBrowserOrigin(request, config) {
  const origin = request?.headers?.origin;
  if (typeof origin !== 'string' || !origin.trim()) return false;

  let parsedOrigin;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    return false;
  }

  // Only accept HTTPS origins matching a known production/preview address.
  // Vercel can route aliases and deployment URLs through different host values,
  // so check the app config, actual host headers, and Vercel's assigned URLs.
  if (parsedOrigin.protocol !== 'https:' || parsedOrigin.username || parsedOrigin.password
      || parsedOrigin.pathname !== '/' || parsedOrigin.search || parsedOrigin.hash) return false;

  const acceptedHosts = new Set();
  const addHost = value => {
    const host = hostFromOriginOrHost(value);
    if (host) acceptedHosts.add(host);
  };

  addHost(config?.publicAppUrl);
  addHost(request?.headers?.host);
  addHost(request?.headers?.['x-forwarded-host']);
  addHost(process.env.VERCEL_URL);
  addHost(process.env.VERCEL_PROJECT_PRODUCTION_URL);
  addHost(process.env.VERCEL_BRANCH_URL);

  return acceptedHosts.has(parsedOrigin.host.toLowerCase());
}
