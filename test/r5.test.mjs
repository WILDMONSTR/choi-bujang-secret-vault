import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import notesHandler from '../api/notes.js';
import noteItemHandler from '../api/notes/[id].js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 4,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  identityProvider: {
    issuer: 'https://zskattfklxijebwsgava.supabase.co/auth/v1',
    jwksUrl: 'https://zskattfklxijebwsgava.supabase.co/auth/v1/.well-known/jwks.json',
    audience: 'authenticated',
  },
  sampleMarker: 'STEP4_OWNER_CHECKED',
  originalApiUrl: null,
  publicAppUrl: 'https://choi-bujang-secret-vault-eosin-zeta.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('배포 식별 정보는 4단계와 이후 단계를 지원한다', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 4,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    originalApiUrl: null,
  });
  const laterStage = deploymentIdentity(env, {
    ...config, step: 5, sampleMarker: 'STEP5_PROTECTED',
    originalApiUrl: 'https://zskattfklxijebwsgava.supabase.co/rest/v1/learning_notes',
  });
  assert.equal(laterStage.step, 5);
  assert.equal(laterStage.sampleMarker, 'STEP5_PROTECTED');
  assert.equal(laterStage.originalApiUrl, 'https://zskattfklxijebwsgava.supabase.co/rest/v1/learning_notes');
  assert.throws(() => deploymentIdentity(env, {
    ...config, step: 5, sampleMarker: 'STEP5_PROTECTED',
    originalApiUrl: 'https://zskattfklxijebwsgava.supabase.co/rest/v1/learning_notes?select=*',
  }));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
  assert.throws(() => deploymentIdentity(env, { ...config, step: 1 }));
});

test('단건 메모 GET·PUT·DELETE는 검증된 사용자 소유 행만 접근한다', async () => {
  const source = await readFile(new URL('../api/notes/[id].js', import.meta.url), 'utf8');
  const getStart = source.indexOf("if (request.method === 'GET') {");
  const putStart = source.indexOf("if (request.method === 'PUT') {", getStart);
  const firstOwnershipComment = source.indexOf(
    '// Access only a row owned by the verified user.',
    putStart,
  );
  const deleteOwnershipComment = source.indexOf(
    '// Access only a row owned by the verified user.',
    firstOwnershipComment + 1,
  );

  assert.ok(getStart >= 0 && putStart > getStart);
  assert.ok(firstOwnershipComment > putStart && deleteOwnershipComment > firstOwnershipComment);

  const getBlock = source.slice(getStart, putStart);
  const putBlock = source.slice(putStart, deleteOwnershipComment);
  const deleteBlock = source.slice(deleteOwnershipComment);

  for (const [method, block] of [
    ['GET', getBlock],
    ['PUT', putBlock],
    ['DELETE', deleteBlock],
  ]) {
    assert.match(
      block,
      /\.eq\('id', id\)\s*\.eq\('owner_id', identity\.userId\)/u,
      `${method} must filter by both memo ID and verified owner ID`,
    );
  }
  assert.match(source, /if \(!data\) return sendError\(response, 404, 'NOT_FOUND'\);/u);
});

test('비로그인 점검은 정적 메모 부재와 모든 CRUD 경로의 자료 없는 거부를 확인한다', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  try {
    globalThis.fetch = async (url, init) => {
      const parsed = new URL(String(url));
      requests.push({ path: parsed.pathname, method: init.method, options: init });
      if (parsed.pathname === '/data.json') return new Response('Not found', { status: 404 });
      if (parsed.pathname === '/api/notes' || parsed.pathname.startsWith('/api/notes/')) {
        return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
          status: 401, headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('Not found', { status: 404 });
    };

    const results = await runAttackChecks(config);
    assert.deepEqual(requests.map(item => [item.path, item.method]), [
      ['/data.json', 'GET'],
      ['/api/notes', 'GET'],
      ['/api/notes', 'POST'],
      ['/api/notes/00000000-0000-4000-8000-000000000001', 'GET'],
      ['/api/notes/00000000-0000-4000-8000-000000000001', 'PUT'],
      ['/api/notes/00000000-0000-4000-8000-000000000001', 'DELETE'],
    ]);
    assert.equal(requests[1].options.headers.Authorization, undefined);
    assert.equal(requests[2].options.headers.Authorization, undefined);
    assert.equal(requests[2].options.headers['Content-Type'], 'application/json');
    assert.match(results.find(item => item.attackId === 'anonymous_static_data_read').observed, /not found/u);
    assert.match(results.find(item => item.attackId === 'anonymous_notes_crud').observed, /All five/u);

    globalThis.fetch = async url => {
      if (new URL(String(url)).pathname === '/data.json') {
        return new Response(JSON.stringify({ notes: [{ title: 'stale', content: 'old public note' }] }), {
          status: 200, headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    };
    const failedStaticCheck = await runAttackChecks(config);
    assert.match(
      failedStaticCheck.find(item => item.attackId === 'anonymous_static_data_read').observed,
      /still reachable/u,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('목록·생성·단건 조회·수정·삭제는 토큰이 없으면 client ID·role과 무관하게 거부한다', async () => {
  const previousUrl = process.env.SUPABASE_URL;
  const previousSecret = process.env.SUPABASE_SECRET_KEY;
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_SECRET_KEY;

  const cases = [
    { handler: notesHandler, request: { method: 'GET', headers: {}, body: { userId: 'fake', role: 'admin' } } },
    { handler: notesHandler, request: { method: 'POST', headers: {}, body: { title: 'fake', body: 'fake', userId: 'fake', role: 'admin' } } },
    ...['GET', 'PUT', 'DELETE'].map(method => ({
      handler: noteItemHandler,
      request: {
        method,
        headers: {},
        query: { id: '00000000-0000-4000-8000-000000000001' },
        body: { title: 'fake', body: 'fake', userId: 'fake', role: 'admin' },
      },
    })),
  ];

  try {
    for (const item of cases) {
      const headers = new Map();
      const result = { statusCode: undefined, body: undefined, ended: false };
      const response = {
        setHeader(name, value) { headers.set(name.toLowerCase(), value); },
        status(code) { result.statusCode = code; return this; },
        json(body) { result.body = body; return this; },
        end() { result.ended = true; return this; },
      };
      await item.handler(item.request, response);
      assert.equal(result.statusCode, 401, item.request.method);
      assert.deepEqual(result.body, { error: 'UNAUTHORIZED' });
      assert.equal(Object.hasOwn(result.body, 'notes'), false);
      assert.equal(Object.hasOwn(result.body, 'id'), false);
      assert.equal(headers.get('cache-control'), 'no-store, max-age=0');
      assert.doesNotMatch(JSON.stringify(result.body), /sb_secret_|SUPABASE_SECRET_KEY/u);
    }

    const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
    assert.doesNotMatch(html, /SUPABASE_SECRET_KEY|sb_secret_|sb_publishable_|SUPABASE_PUBLISHABLE_KEY|SUPABASE_PROJECT_URL/u);
    assert.doesNotMatch(html, /@supabase\/supabase-js|signInWithPassword|access_token|Authorization:\s*['"]Bearer/u);
    assert.match(html, /authRequest\(['"]\/api\/auth\/login['"]/u);
    assert.match(html, /authRequest\(['"]\/api\/auth\/session['"]/u);
    assert.match(html, /authRequest\(['"]\/api\/auth\/logout['"]/u);

    const loginRoute = await readFile(new URL('../api/auth/login.js', import.meta.url), 'utf8');
    const sessionRoute = await readFile(new URL('../api/auth/session.js', import.meta.url), 'utf8');
    const logoutRoute = await readFile(new URL('../api/auth/logout.js', import.meta.url), 'utf8');
    assert.match(loginRoute, /HttpOnly|setSessionCookies/u);
    assert.match(sessionRoute, /refreshSession|setSessionCookies/u);
    assert.match(logoutRoute, /clearSessionCookies/u);
  } finally {
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousSecret === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousSecret;
  }
});
