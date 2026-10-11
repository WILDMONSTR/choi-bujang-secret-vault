import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const publicDir = resolve(root, 'public');
const legacyDataFile = resolve(publicDir, 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

if (!Number.isInteger(config.step) || config.step < 2 || config.step > 12
    || typeof config.sampleMarker !== 'string'
    || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
  throw new Error('2~12단계 설정을 확인하세요. 공개 빌드에는 유효한 sampleMarker가 필요합니다.');
}

await mkdir(publicDir, { recursive: true });

// Do not publish or recreate the old static data endpoint.
await rm(legacyDataFile, { force: true });
console.log('공개 data.json을 생성하지 않도록 확인했습니다.');

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(publicDir, 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
