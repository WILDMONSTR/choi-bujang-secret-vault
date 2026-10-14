import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const baseline = JSON.parse(await readFile(new URL('../package/baseline-functions.json', import.meta.url)));

async function listApiFiles(directory, prefix = 'api') {
  const entries = await readdir(directory, { withFileTypes: true });
  const found = [];
  for (const entry of entries) {
    const relative = join(prefix, entry.name).replaceAll('\\', '/');
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...await listApiFiles(absolute, relative));
    else if (/\\.(?:m?js|ts)$/u.test(entry.name)) found.push(relative);
  }
  return found.sort();
}

test('패키징 함수 기준표는 중첩 경로를 포함한 실제 API와 일치한다', async () => {
  const actual = await listApiFiles(fileURLToPath(new URL('../api/', import.meta.url)));
  assert.equal(baseline.version, 1);
  assert.equal(baseline.starter, 'ChoiTimo/aleph-defense-starter');
  assert.deepEqual(baseline.functions, []);
  assert.deepEqual(baseline.allowedNew, [
    'api/ai.js',
    'api/announcements.js',
    'api/announcements/[id].js',
    'api/auth/login.js',
    'api/auth/logout.js',
    'api/auth/session.js',
    'api/devices.js',
    'api/devices/approve-self.js',
    'api/devices/approve.js',
    'api/devices/register.js',
    'api/notes.js',
    'api/notes/[id].js',
    'api/stage10/memo-restore.js',
    'api/stage10/policy-diff.js',
    'api/stage10/policy-restore.js',
    'api/threat-intel.js'
  ]);
  assert.deepEqual(actual, [...baseline.functions, ...baseline.allowedNew].sort());
});

test('미구현 서버 뼈대는 성공이나 로그인 통과로 가장하지 않는다', async () => {
  for (const name of ['ai', 'threat-intel']) {
    const { default: handler } = await import(`../api/${name}.js`);
    const headers = new Map();
    let status;
    let body;
    handler({}, {
      setHeader: (key, value) => headers.set(key.toLowerCase(), value),
      status: value => { status = value; return { json: value => { body = value; } }; },
    });
    assert.equal(status, 501);
    assert.equal(headers.get('cache-control'), 'no-store');
    assert.match(body.error, /NOT_IMPLEMENTED$/u);
  }
});

test('P7 시작 틀 안내는 실제 빌드 조건과 새 배포 시험에 맞는다', async () => {
  const readme = await readFile(new URL('../package/README.md', import.meta.url), 'utf8');
  const selfCheck = await readFile(new URL('../package/SELF-CHECK.md', import.meta.url), 'utf8');
  assert.match(readme, /새 Vercel 프로젝트/u);
  assert.match(readme, /Vercel이 제공하는 저장소·커밋·배포 URL 정보/u);
  assert.doesNotMatch(readme, /npm start/u);
  assert.match(selfCheck, /P7-3\\.png/u);
});
