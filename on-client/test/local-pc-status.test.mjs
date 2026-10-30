import test from 'node:test';
import assert from 'node:assert/strict';
import { readLocalPcStatus } from '../src/local-pc-status.mjs';

const fixed = () => new Date('2026-10-30T00:00:00.000Z');
const measuredAt = '2026-10-30T00:00:00.000Z';
function fakeRun(payload, error = null) {
  return (_command, args, options, callback) => {
    assert.equal(_command, 'powershell.exe');
    assert.ok(args.includes('-NoProfile'));
    assert.ok(args.includes('-NonInteractive'));
    assert.ok(!args.includes('-Verb'));
    assert.ok(!args.includes('RunAs'));
    assert.equal(options.windowsHide, true);
    callback(error, typeof payload === 'string' ? payload : JSON.stringify(payload));
  };
}
test('Windows records three separate real observations with units and timestamps', async () => {
  const data = {
    cpu: { status: 'ok', usedPercent: 12, measuredAt },
    memory: { status: 'ok', usedGiB: 8, totalGiB: 16, usedPercent: 50, measuredAt },
    disk: { status: 'ok', freeGiB: 80, totalGiB: 200, drive: 'C:', measuredAt },
  };
  const r = await readLocalPcStatus({ platform: 'win32', execFileImpl: fakeRun(data), now: fixed });
  assert.equal(r.source, 'local-windows');
  assert.equal(r.checkedAt, measuredAt);
  assert.deepEqual(r.cpu, { status: 'ok', usedPercent: 12, unit: '%', measuredAt, reason: null });
  assert.equal(r.memory.unit, 'GiB');
  assert.equal(r.disk.unit, 'GiB');
  assert.equal(r.disk.drive, 'C:');
});
test('A missing CPU reading stays unavailable while other readings survive', async () => {
  const d = {
    cpu: { status: 'unavailable', usedPercent: null, measuredAt: null, reason: 'CPU_READ_FAILED' },
    memory: { status: 'ok', usedGiB: 3, totalGiB: 8, usedPercent: 37.5, measuredAt },
    disk: { status: 'unavailable', reason: 'DISK_READ_FAILED' },
  };
  const r = await readLocalPcStatus({ platform: 'win32', execFileImpl: fakeRun(d), now: fixed });
  assert.equal(r.cpu.status, 'unavailable');
  assert.equal(r.cpu.usedPercent, null);
  assert.equal(r.cpu.measuredAt, null);
  assert.equal(r.cpu.reason, 'CPU_READ_FAILED');
  assert.equal(r.memory.status, 'ok');
  assert.equal(r.disk.reason, 'DISK_READ_FAILED');
});
test('Invalid measurements never become actual values', async () => {
  const r = await readLocalPcStatus({ platform: 'win32', execFileImpl: fakeRun({
    cpu: { status: 'ok', usedPercent: 200, measuredAt },
    memory: { status: 'ok', usedGiB: 20, totalGiB: 8, usedPercent: 250, measuredAt },
    disk: { status: 'ok', freeGiB: -5, totalGiB: 100, drive: 'C:', measuredAt },
  }), now: fixed });
  for (const item of [r.cpu, r.memory, r.disk]) {
    assert.equal(item.status, 'unavailable');
    assert.equal(item.measuredAt, null);
  }
});
test('Missing PowerShell and unparseable output never show example values', async () => {
  const failure = await readLocalPcStatus({ platform: 'win32', execFileImpl: fakeRun('', { code: 'ENOENT' }), now: fixed });
  assert.equal(failure.cpu.reason, 'POWERSHELL_NOT_FOUND');
  const malformed = await readLocalPcStatus({ platform: 'win32', execFileImpl: fakeRun('not json'), now: fixed });
  assert.equal(malformed.disk.reason, 'INVALID_RESPONSE');
});
test('Non-Windows platform reads nothing and reports a reason', async () => {
  const r = await readLocalPcStatus({ platform: 'linux', execFileImpl: () => { throw Error('should not run'); }, now: fixed });
  assert.equal(r.memory.status, 'unavailable');
  assert.equal(r.memory.reason, 'UNSUPPORTED_PLATFORM');
  assert.equal(r.cpu.measuredAt, null);
});
