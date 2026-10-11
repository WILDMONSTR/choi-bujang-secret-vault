import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

if (config.step !== 2 || config.sampleMarker !== 'STEP2_PROTECTED') {
  throw new Error('현재 공개 빌드는 2단계 전용입니다. aleph.config.json의 단계를 확인하세요.');
}

await mkdir(resolve(root, 'public'), { recursive: true });

// 공개 정적 경로에는 메모 본문을 쓰지 않습니다.
// 가상 메모의 학습용 사본은 supabase/learning-notes.sql에만 포함됩니다.
const publicData = { sampleMarker: config.sampleMarker, notes: [] };
await writeFile(output, `${JSON.stringify(publicData, null, 2)}\n`, 'utf8');
console.log('공개 data.json을 빈 메모 목록으로 생성했습니다.');

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
