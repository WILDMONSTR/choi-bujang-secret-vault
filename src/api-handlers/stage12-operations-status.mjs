import config from '../../aleph.config.json' with { type: 'json' };
import { requireResourceIdentity, sendResourceError } from '../resource-access.mjs';
import { requireApprovedDevice } from '../require-approved-device.mjs';
import { readDeviceCredential } from '../device-cookie.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }

  const auth = await requireResourceIdentity(req, res, config);
  if (!auth) return;
  if (!await requireApprovedDevice(req, res, auth)) return;

  try {
    const db = auth.supabase;
    const ownerId = auth.identity.userId;
    const currentCredential = readDeviceCredential(req);
    const [devicesResult, recoveryResult, revocationResult] = await Promise.all([
      db.from('app_devices')
        .select('id,label,status,created_at,approved_at,last_seen_at')
        .eq('owner_id', ownerId).order('created_at', { ascending: false }).limit(50),
      db.from('stage10_restore_audit')
        .select('audit_id,action,resource_kind,resource_key,before_sha256,after_sha256,created_at,details')
        .eq('actor_id', ownerId).order('created_at', { ascending: false }).limit(10),
      db.from('stage12_device_revocation_audit')
        .select('revocation_id,device_id,status,created_at')
        .eq('actor_id', ownerId).order('created_at', { ascending: false }).limit(10),
    ]);

    if (devicesResult.error || !Array.isArray(devicesResult.data)) {
      return sendResourceError(res, 503, 'DEVICE_REGISTRY_UNAVAILABLE');
    }

    const devices = devicesResult.data.map((item) => ({
      deviceId: item.id,
      label: item.label,
      status: item.status,
      createdAt: item.created_at,
      approvedAt: item.approved_at,
      lastSeenAt: item.last_seen_at,
    }));
    const counts = { approved: 0, pending: 0, revoked: 0, other: 0 };
    for (const item of devices) {
      if (Object.hasOwn(counts, item.status)) counts[item.status] += 1;
      else counts.other += 1;
    }

    const recoveryAvailable = !recoveryResult.error && Array.isArray(recoveryResult.data);
    const revocationAvailable = !revocationResult.error && Array.isArray(revocationResult.data);
    const recoveryRecords = recoveryAvailable ? recoveryResult.data.map((item) => ({
      auditId: item.audit_id,
      action: item.action,
      resourceKind: item.resource_kind,
      scope: typeof item.details?.scope === 'string' ? item.details.scope : null,
      resourceKey: item.resource_key,
      beforeSha256: item.before_sha256,
      afterSha256: item.after_sha256,
      createdAt: item.created_at,
    })) : [];
    const revocationRecords = revocationAvailable ? revocationResult.data.map((item) => ({
      revocationId: item.revocation_id,
      deviceId: item.device_id,
      status: item.status,
      createdAt: item.created_at,
    })) : [];

    return res.status(200).json({
      observedAt: new Date().toISOString(),
      authorization: {
        authenticated: true,
        currentDeviceId: currentCredential?.deviceId || null,
        currentDeviceStatus: devices.find((item) => item.deviceId === currentCredential?.deviceId)?.status || 'unknown',
        source: 'server-verified session + public.app_devices',
      },
      devices: {
        source: 'public.app_devices',
        count: devices.length,
        counts,
        items: devices,
      },
      revocation: {
        available: revocationAvailable,
        source: 'public.stage12_device_revocation_audit',
        records: revocationRecords,
        errorCode: revocationAvailable ? null : 'REVOCATION_HISTORY_UNAVAILABLE',
      },
      recovery: {
        available: recoveryAvailable,
        source: 'public.stage10_restore_audit',
        records: recoveryRecords,
        errorCode: recoveryAvailable ? null : 'RESTORE_AUDIT_UNAVAILABLE',
      },
      studentCode: {
        decisionSource: 'src/decider.mjs',
        detectionSource: 'src/detect.mjs',
        decisionHistoryAvailable: false,
        detectionHistoryAvailable: false,
        note: '학생 코드의 실제 실행 출력은 별도 자기 점검 API로 지금 실행합니다. 이 자료실에는 외부 심판의 과거 판정·탐지 기록이 저장되어 있지 않습니다.',
      },
      providedEngine: {
        issuer: config.judgeIssuer,
        source: 'aleph.config.json',
        resultQueryAvailable: false,
        note: '심판 접수 주소와 판정 결과 조회 API는 다릅니다. 이 주소만으로 41종 시험 결과를 조회했다고 처리하지 않습니다.',
      },
    });
  } catch {
    return sendResourceError(res, 503, 'OPERATIONS_STATUS_UNAVAILABLE');
  }
}
