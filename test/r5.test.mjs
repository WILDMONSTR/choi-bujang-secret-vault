import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import notesHandler from '../api/notes.js';
import noteItemHandler from '../api/notes/[id].js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 3,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  identityProvider: {
    issuer: 'https://zskattfklxijebwsgava.supabase.co/auth/v1',
    jwksUrl: 'https://zskattfklxijebwsgava.supabase.co/auth/v1/.well-known/jwks.json',
    audience: 'authenticated',
  },
  sampleMarker: 'STEP3_PROTECTED',
  publicAppUrl: 'https://choi-bujang-secret-vault-eosin-zeta.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('배포 식별 정보는 3단계와 이후 단계를 지원한다', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 3,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  const laterStage = deploymentIdentity(env, {
    ...config, step: 4, sampleMarker: 'STEP4_PROTECTED',
  });
  assert.equal(laterStage.step, 4);
  assert.equal(laterStage.sampleMarker, 'STEP4_PROTECTED');
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
  assert.throws(() => deploymentIdentity(env, { ...config, step: 1 }));
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
    assert.doesNotMatch(html, /SUPABASE_SECRET_KEY|sb_secret_/u);
    assert.match(html, /Authorization: 'Bearer ' \+ token/u);
  } finally {
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousSecret === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousSecret;
  }
});
