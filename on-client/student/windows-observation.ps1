# Read-only queries. Never requests elevation or changes system/security settings.
param([ValidateSet('network','firewall','system','application')][string]$Section,
      [string]$StartUtc, [string]$EndUtc)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
  $data = $null
  switch ($Section) {
    'network' {
      $data = @(Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
        [ordered]@{
          name = [string]$_.InterfaceAlias
          status = [string]$_.NetAdapter.Status
          addresses = @(@($_.IPv4Address) + @($_.IPv6Address) | Where-Object { $_ } | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
          gateways = @(@($_.IPv4DefaultGateway) + @($_.IPv6DefaultGateway) | Where-Object { $_ } | ForEach-Object { [string]$_.NextHop })
          dns = @($_.DNSServer | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | ForEach-Object { [string]$_ })
        }
      })
    }
    'firewall' {
      $data = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
        [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction }
      })
    }
    default {
      $log = if ($Section -eq 'system') { 'System' } else { 'Application' }
      $start = [DateTimeOffset]::Parse($StartUtc).UtcDateTime
      $end = [DateTimeOffset]::Parse($EndUtc).UtcDateTime
      $events = @()
      try {
        # Limit bounds memory/runtime. A limited result is explicitly partial, never a full-window total.
        $events = @(Get-WinEvent -FilterHashtable @{LogName=$log; Level=@(2,3); StartTime=$start; EndTime=$end} -MaxEvents 5001 -ErrorAction Stop)
      } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
      }
      $partial = $events.Count -gt 5000
      $events = @($events | Select-Object -First 5000)
      $data = [ordered]@{ log=$log; warning=@($events | Where-Object Level -eq 3).Count; error=@($events | Where-Object Level -eq 2).Count; unit='건'; partial=$partial; limit=5000; startUtc=$StartUtc; endUtc=$EndUtc }
    }
  }
  [ordered]@{status='ok'; observedAt=[DateTime]::UtcNow.ToString('o'); data=$data} | ConvertTo-Json -Depth 8 -Compress
} catch {
  $reason = if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception -is [System.Security.SecurityException] -or $_.FullyQualifiedErrorId -match 'Unauthorized|AccessDenied|PermissionDenied' -or $_.CategoryInfo.Category -eq 'PermissionDenied' -or $_.Exception.NativeErrorCode -eq 5) { 'ACCESS_DENIED' }
    elseif ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { 'COMMAND_UNAVAILABLE' } else { 'QUERY_FAILED' }
  [ordered]@{status='unavailable'; observedAt=[DateTime]::UtcNow.ToString('o'); reason=$reason} | ConvertTo-Json -Compress
}
