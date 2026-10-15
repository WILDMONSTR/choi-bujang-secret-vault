import config from '../../aleph.config.json' with { type: 'json' };
import { detect } from '../detect.mjs';
import { requireResourceIdentity, sendResourceError } from '../resource-access.mjs';
import { requireApprovedDevice } from '../require-approved-device.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;
  if (!await requireApprovedDevice(req, res, auth)) return;

  try {
    const start = Date.now() - 30_000;
    const events = Array.from({ length: 121 }, (_, index) => ({
      at: new Date(start + index * 200).toISOString(),
      method: 'GET',
      identity: { sub: 'synthetic-subject-only' },
    }));
    const actual = detect(events);
    const passed = actual?.action === 'propose_revocation'
      && actual?.reasonCode === 'burst_read'
      && actual?.subject === 'synthetic-subject-only'
      && Object.keys(actual).sort().join(',') === 'action,reasonCode,subject';

    return res.status(200).json({
      source: { owner: 'student', file: 'src/detect.mjs', revision: process.env.VERCEL_GIT_COMMIT_SHA || null },
      mode: 'synthetic-detection-fixture',
      executedAt: new Date().toISOString(),
      inputEventCount: events.length,
      actual,
      expected: { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'synthetic-subject-only' },
      passed,
      revocationPerformed: false,
      note: '탐지기 코드의 가상 사건 결과입니다. 이 함수는 회수를 제안할 뿐 실제 기기나 계정 권한을 회수하지 않습니다.',
    });
  } catch {
    return sendResourceError(res, 500, 'STUDENT_DETECTION_CHECK_FAILED');
  }
}
