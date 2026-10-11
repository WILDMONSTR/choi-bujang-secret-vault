import { createClient } from '@supabase/supabase-js';

const NOTE_TITLES = Object.freeze([
  '과제',
  '포트폴리오',
  '아침 리추얼',
  '훈련 행정 자료',
]);

function sendError(response, status, code) {
  return response.status(status).json({ error: code });
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return sendError(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const configuredUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (typeof configuredUrl !== 'string' || !configuredUrl.trim()
      || typeof secretKey !== 'string' || !secretKey.trim()) {
    return sendError(response, 503, 'NOT_CONFIGURED');
  }

  let supabaseUrl;
  try {
    const parsedUrl = new URL(configuredUrl);
    if (parsedUrl.protocol !== 'https:' || !parsedUrl.hostname
        || parsedUrl.username || parsedUrl.password
        || parsedUrl.pathname !== '/' || parsedUrl.search || parsedUrl.hash) {
      return sendError(response, 503, 'NOT_CONFIGURED');
    }
    supabaseUrl = parsedUrl.origin;
  } catch {
    return sendError(response, 503, 'NOT_CONFIGURED');
  }

  try {
    const supabase = createClient(supabaseUrl, secretKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    });

    const { data, error } = await supabase
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

    // Only the four intended virtual notes are returned. Never return env values,
    // request headers, raw Supabase errors, or server configuration.
    return response.status(200).json({ notes });
  } catch {
    // Do not log the exception: upstream errors may contain sensitive details.
    return sendError(response, 502, 'NOTES_UNAVAILABLE');
  }
}
