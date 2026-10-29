# Mocked PowerShell cmdlets on Windows CI. No guest, VMware or network probes.
$ErrorActionPreference = 'Stop'
function Get-NetAdapter { param([switch]$IncludeHidden, [string]$ErrorAction)
    @([pscustomobject]@{Name='Ethernet0';Status='Up';ifIndex=7},
      [pscustomobject]@{Name='Ethernet1';Status='Disabled';ifIndex=8})
}
function Get-NetIPAddress { param([string]$AddressFamily, [string]$ErrorAction)
    if ($AddressFamily -eq 'IPv4') { [pscustomobject]@{InterfaceIndex=7;IPAddress='192.168.77.10';PrefixLength=24} }
    else { [pscustomobject]@{InterfaceIndex=7;IPAddress='fe80::12';PrefixLength=64} }
}
function Get-NetRoute { param([string]$AddressFamily, [string]$ErrorAction) @() }
function Get-DnsClientServerAddress { param([string]$AddressFamily, [string]$ErrorAction) @() }
$target = Join-Path $env:TEMP ('da005-guest-' + [guid]::NewGuid().ToString() + '.json')
try {
    $script = Join-Path $PSScriptRoot '../scripts/collect_windows_guest_network_snapshot.ps1'
    $messages = @(& $script -OutputPath $target)
    if (-not (Test-Path -LiteralPath $target)) { throw 'No guest snapshot produced' }
    $snapshot = Get-Content -LiteralPath $target -Raw | ConvertFrom-Json
    if ($snapshot.schema_version -ne 1 -or $snapshot.adapters.Count -ne 2 -or
        $snapshot.adapters[0].ipv4[0].address -ne '192.168.77.10' -or
        $snapshot.adapters[0].ipv6[0] -ne 'fe80::12') { throw 'Wrong guest snapshot contract' }
    if (@($snapshot.default_routes_ipv4).Count -ne 0 -or @($snapshot.default_routes_ipv6).Count -ne 0) { throw 'Routes present' }
    if (-not ($messages -join ' ').Contains('NOT verified')) { throw 'Missing isolation disclaimer' }
    $refused = $false
    try { & $script -OutputPath $target | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'Guest snapshot was overwritten' }
    Write-Output 'Mocked Windows guest snapshot smoke passed; no VMware tested.'
}
finally { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
