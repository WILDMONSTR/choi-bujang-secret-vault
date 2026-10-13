import {
  requireStage10TestOwner,
  stage10ErrorResponse,
} from '../../src/stage10-recovery-api.mjs';
import { isUuid, validateMemoBackup } from '../../src/stage10-recovery.mjs';
import {
  requireZoneMembership,
  sendResourceError,
} from '../../src/resource-access.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendResourceError(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const auth = await requireStage10TestOwner(req, res);
  if (!auth) return;

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = null; }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || body.confirm !== true || !isUuid(body.backupId) || !isUuid(body.noteId)
      || !isUuid(body.ownerId) || body.ownerId.toLowerCase() !== auth.identity.userId.toLowerCase()
      || typeof body.contentSha256 !== 'string'
      || !SHA256.test(body.contentSha256.toLowerCase())) {
    return sendResourceError(res, 400, 'CONFIRMATION_REQUIRED');
  }

  try {
    const { data: backup, error: backupError } = await auth.supabase
      .from('stage10_memo_backups')
      .select('backup_id,note_id,owner_id,zone_id,title,content,content_sha256,validated,captured_at,validated_at,incident_at')
      .eq('backup_id', body.backupId).maybeSingle();
    if (backupError) return sendResourceError(res, 503, 'RESTORE_STORAGE_UNAVAILABLE');
    if (!backup) return sendResourceError(res, 409, 'MEMO_BACKUP_UNAVAILABLE');

    const verified = validateMemoBackup(backup, {
      expectedBackupId: body.backupId,
      noteId: body.noteId,
      ownerId: auth.identity.userId,
      contentSha256: body.contentSha256.toLowerCase(),
    });
    if (verified.noteId !== body.noteId || verified.ownerId !== auth.identity.userId) {
      return sendResourceError(res, 409, 'MEMO_BACKUP_INVALID');
    }

    const membership = await requireZoneMembership(auth.supabase, auth.identity.userId, verified.zoneId, {
      roles: ['student', 'instructor'],
    });
    if (!membership || membership.zone.zone_id !== verified.zoneId) {
      return sendResourceError(res, 404, 'NOT_FOUND');
    }

    const { data, error } = await auth.supabase.rpc('stage10_restore_virtual_memo', {
      p_backup_id: verified.backupId,
      p_note_id: verified.noteId,
      p_owner_id: verified.ownerId,
      p_zone_id: verified.zoneId,
      p_title: backup.title,
      p_content: backup.content,
      p_expected_content_sha256: verified.contentSha256,
      p_actor_id: auth.identity.userId,
    });
    if (error) {
      const message = String(error.message ?? '');
      if (message.includes('MEMO_OWNER_MISMATCH')) {
        return sendResourceError(res, 409, 'MEMO_OWNER_MISMATCH');
      }
      if (message.includes('MEMO_BACKUP')) {
        return sendResourceError(res, 409, 'MEMO_BACKUP_INVALID');
      }
      if (error.code === '23505') return sendResourceError(res, 409, 'MEMO_RESTORE_CONFLICT');
      return sendResourceError(res, 502, 'MEMO_RESTORE_FAILED');
    }
    if (!data || data.id !== verified.noteId || data.ownerId !== verified.ownerId
        || data.contentSha256 !== verified.contentSha256 || typeof data.auditId !== 'string') {
      return sendResourceError(res, 502, 'MEMO_RESTORE_FAILED');
    }
    return res.status(200).json({
      restored: true,
      service: 'learning_notes',
      route: 'POST /api/stage10/memo-restore',
      id: data.id,
      ownerId: data.ownerId,
      contentSha256: data.contentSha256,
      auditId: data.auditId,
    });
  } catch (error) {
    return stage10ErrorResponse(res, error);
  }
}
