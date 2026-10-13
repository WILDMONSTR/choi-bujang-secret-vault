import assert from 'node:assert/strict';
import { formatResourceId, parseResourceId } from '../src/resource-id.mjs';

const id = 'b93c5f7d-1e4b-4556-bf0f-d1b69f7e46fd';
const otherId = '00c98ad7-4ea2-4a0e-8d63-191cf2c8ae9c';
const checks = [
  ['메모 ID에 memo 접두사 부여', () => assert.equal(formatResourceId('memo', id), `memo:${id}`)],
  ['강사 공지 ID에 instructor-announcement 접두사 부여',
    () => assert.equal(formatResourceId('instructor-announcement', id), `instructor-announcement:${id}`)],
  ['기존 UUID 메모 경로 계속 지원', () => assert.equal(parseResourceId(id, 'memo'), id)],
  ['유형이 붙은 메모 ID 해석', () => assert.equal(parseResourceId(`memo:${id}`, 'memo'), id)],
  ['URL 인코딩된 메모 ID 해석', () => assert.equal(parseResourceId(`memo%3A${id}`, 'memo'), id)],
  ['유형이 붙은 강사 공지 ID 해석',
    () => assert.equal(parseResourceId(`instructor-announcement:${id}`, 'instructor-announcement'), id)],
  ['URL 인코딩된 강사 공지 ID 해석',
    () => assert.equal(parseResourceId(`instructor-announcement%3A${id}`, 'instructor-announcement'), id)],
  ['강사 공지 ID를 메모 API에 전달하면 거부',
    () => assert.equal(parseResourceId(`instructor-announcement:${id}`, 'memo'), null)],
  ['메모 ID를 강사 공지 API에 전달하면 거부',
    () => assert.equal(parseResourceId(`memo:${id}`, 'instructor-announcement'), null)],
  ['잘못된 UUID는 거부', () => assert.equal(parseResourceId('memo:not-a-uuid', 'memo'), null)],
  ['없는 자원 유형은 거부', () => assert.throws(() => formatResourceId('unknown', otherId), /INVALID_RESOURCE_ID/)],
];

for (const [name, run] of checks) {
  run();
  process.stdout.write(`통과 · ${name}\n`);
}
process.stdout.write(`전체 ${checks.length}개 자원 ID 테스트 통과\n`);
