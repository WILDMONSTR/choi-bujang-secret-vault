// Read-only Windows PC measurements. No admin rights, files, registry writes, or external dependencies.
import { execFile } from 'node:child_process';

const POWER_SHELL = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Stamp { (Get-Date).ToUniversalTime().ToString('o') }
$result = [ordered]@{
  cpu = [ordered]@{ status = 'unavailable'; usedPercent = $null; measuredAt = $null; reason = 'CPU_VALUE_UNAVAILABLE' }
  memory = [ordered]@{ status = 'unavailable'; usedGiB = $null; totalGiB = $null; usedPercent = $null; measuredAt = $null; reason = 'MEMORY_VALUE_UNAVAILABLE' }
  disk = [ordered]@{ status = 'unavailable'; freeGiB = $null; totalGiB = $null; drive = $null; measuredAt = $null; reason = 'DISK_TARGET_UNAVAILABLE' }
}
try {
  $loads = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Where-Object { $null -ne $_.LoadPercentage } | ForEach-Object { [double]$_.LoadPercentage })
  if ($loads.Count -gt 0) {
    $value = [math]::Round([double](($loads | Measure-Object -Average).Average), 1)
    if ($value -ge 0 -and $value -le 100) {
      $result.cpu = [ordered]@{ status = 'ok'; usedPercent = $value; measuredAt = (Stamp); reason = $null }
    }
  }
} catch { $result.cpu.reason = 'CPU_READ_FAILED' }
try {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  $total = [double]$os.TotalVisibleMemorySize
  $free = [double]$os.FreePhysicalMemory
  if ($total -gt 0 -and $free -ge 0 -and $free -le $total) {
    $result.memory = [ordered]@{
      status = 'ok'
      usedGiB = [math]::Round(($total - $free) / 1048576, 2)
      totalGiB = [math]::Round($total / 1048576, 2)
      usedPercent = [math]::Round((($total - $free) / $total) * 100, 1)
      measuredAt = (Stamp)
      reason = $null
    }
  }
} catch { $result.memory.reason = 'MEMORY_READ_FAILED' }
try {
  $systemDrive = [Environment]::GetEnvironmentVariable('SystemDrive')
  if ($systemDrive -match '^[A-Za-z]:$') {
    $drive = [System.IO.DriveInfo]::new($systemDrive)
    if ($drive.IsReady -and $drive.TotalSize -gt 0 -and $drive.AvailableFreeSpace -ge 0 -and $drive.AvailableFreeSpace -le $drive.TotalSize) {
      $result.disk = [ordered]@{
        status = 'ok'
        freeGiB = [math]::Round($drive.AvailableFreeSpace / 1073741824, 2)
        totalGiB = [math]::Round($drive.TotalSize / 1073741824, 2)
        drive = $systemDrive
        measuredAt = (Stamp)
        reason = $null
      }
    }
  }
} catch { $result.disk.reason = 'DISK_READ_FAILED' }
$result | ConvertTo-Json -Depth 4 -Compress
`;

const unknown = (reason) => ({
  cpu: { status: 'unavailable', usedPercent: null, unit: '%', measuredAt: null, reason },
  memory: { status: 'unavailable', usedGiB: null, totalGiB: null, usedPercent: null, unit: 'GiB', measuredAt: null, reason },
  disk: { status: 'unavailable', freeGiB: null, totalGiB: null, drive: null, unit: 'GiB', measuredAt: null, reason },
});
const finite = (n, min, max) => typeof n === 'number' && Number.isFinite(n) && n >= min && n <= max;
const stamp = (s) => typeof s === 'string' && /^\d{4}-\d\d-\d\dT/.test(s) && Number.isFinite(Date.parse(s)) ? s : null;
const reason = (s, fallback) => typeof s === 'string' && /^[A-Z_]{3,40}$/.test(s) ? s : fallback;

function normalize(raw) {
  const base = unknown('INVALID_MEASUREMENT');
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return base;
  const c = raw.cpu;
  if (c && c.status === 'ok' && finite(c.usedPercent, 0, 100) && stamp(c.measuredAt)) {
    base.cpu = { status: 'ok', usedPercent: c.usedPercent, unit: '%', measuredAt: c.measuredAt, reason: null };
  } else if (c?.status === 'unavailable') base.cpu.reason = reason(c.reason, 'CPU_VALUE_UNAVAILABLE');
  const m = raw.memory;
  if (m && m.status === 'ok' && finite(m.totalGiB, 0.001, Number.MAX_SAFE_INTEGER)
      && finite(m.usedGiB, 0, m.totalGiB) && finite(m.usedPercent, 0, 100) && stamp(m.measuredAt)) {
    base.memory = { status: 'ok', usedGiB: m.usedGiB, totalGiB: m.totalGiB,
      usedPercent: m.usedPercent, unit: 'GiB', measuredAt: m.measuredAt, reason: null };
  } else if (m?.status === 'unavailable') base.memory.reason = reason(m.reason, 'MEMORY_VALUE_UNAVAILABLE');
  const d = raw.disk;
  if (d && d.status === 'ok' && finite(d.totalGiB, 0.001, Number.MAX_SAFE_INTEGER)
      && finite(d.freeGiB, 0, d.totalGiB) && /^[A-Za-z]:$/.test(d.drive) && stamp(d.measuredAt)) {
    base.disk = { status: 'ok', freeGiB: d.freeGiB, totalGiB: d.totalGiB,
      drive: d.drive, unit: 'GiB', measuredAt: d.measuredAt, reason: null };
  } else if (d?.status === 'unavailable') base.disk.reason = reason(d.reason, 'DISK_TARGET_UNAVAILABLE');
  return base;
}

/** Returns actual measurements only; failed/unavailable readings are never demo values. */
export function readLocalPcStatus({ platform = process.platform, execFileImpl = execFile, now = () => new Date() } = {}) {
  const wrap = (metrics) => ({ source: 'local-windows', checkedAt: now().toISOString(), ...metrics });
  if (platform !== 'win32') return Promise.resolve(wrap(unknown('UNSUPPORTED_PLATFORM')));
  return new Promise((resolve) => {
    // -Command executes a fixed read-only query. No script files, admin elevation or shell.
    execFileImpl('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', POWER_SHELL],
      { timeout: 12000, maxBuffer: 65536, windowsHide: true }, (error, stdout) => {
        if (error) {
          const code = error.code === 'ENOENT' ? 'POWERSHELL_NOT_FOUND'
            : error.killed ? 'MEASUREMENT_TIMEOUT' : 'MEASUREMENT_FAILED';
          resolve(wrap(unknown(code)));
          return;
        }
        try { resolve(wrap(normalize(JSON.parse(String(stdout).replace(/^\uFEFF/, '').trim())))); }
        catch { resolve(wrap(unknown('INVALID_RESPONSE'))); }
      });
  });
}
