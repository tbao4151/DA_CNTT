# GitHub Windows CI uses mocked NetTCPIP cmdlets: no real adapter access or traffic.
$ErrorActionPreference = 'Stop'
function Get-NetAdapter { param([string]$Name, [string]$ErrorAction) [pscustomobject]@{ Name = $Name; ifIndex = 11; Status = 'Up' } }
function Get-NetIPAddress { param([int]$InterfaceIndex, [string]$AddressFamily, [string]$ErrorAction) [pscustomobject]@{ IPAddress = '192.168.77.1'; PrefixLength = 24 } }
function Get-NetRoute { param([int]$InterfaceIndex, [string]$AddressFamily, [string]$ErrorAction) @() }
function Get-DnsClientServerAddress { param([int]$InterfaceIndex, [string]$AddressFamily, [string]$ErrorAction) [pscustomobject]@{ ServerAddresses = @() } }
$target = Join-Path $env:TEMP ("da005-hostonly-" + [guid]::NewGuid().ToString() + '.json')
try {
    $collector = Join-Path $PSScriptRoot '../scripts/collect_windows_hostonly_snapshot.ps1'
    $messages = @(& $collector -AdapterName 'VMware Network Adapter VMnet1' -OutputPath $target)
    if (-not (Test-Path -LiteralPath $target)) { throw 'Snapshot not created' }
    $snapshot = Get-Content -LiteralPath $target -Raw | ConvertFrom-Json
    if ($snapshot.schema_version -ne 1 -or $snapshot.adapter_ipv4[0].address -ne '192.168.77.1') { throw 'Unexpected snapshot' }
    if (@($snapshot.adapter_default_routes).Count -ne 0 -or @($snapshot.adapter_dns_servers).Count -ne 0) { throw 'Unexpected route or DNS' }
    if (-not ($messages -join ' ').Contains('NOT verified')) { throw 'Missing safety disclaimer' }
    $refused = $false
    try { & $collector -AdapterName 'VMware Network Adapter VMnet1' -OutputPath $target | Out-Null }
    catch { $refused = $true }
    if (-not $refused) { throw 'Existing snapshot was overwritten' }
    # An in-repository absolute path must fail before any sensitive JSON is written.
    $repoTarget = Join-Path $PSScriptRoot ('da005-hostonly-private-' + [guid]::NewGuid().ToString() + '.json')
    try {
        $blocked = $false
        try { & $collector -AdapterName 'VMware Network Adapter VMnet1' -OutputPath $repoTarget | Out-Null }
        catch { $blocked = $true }
        if (-not $blocked -or (Test-Path -LiteralPath $repoTarget)) {
            throw 'Collector accepted an in-repository evidence destination'
        }
    }
    finally { Remove-Item -LiteralPath $repoTarget -Force -ErrorAction SilentlyContinue }
    $relativeTarget = '.\\da005-hostonly-relative-' + [guid]::NewGuid().ToString() + '.json'
    try {
        $blocked = $false
        try { & $collector -AdapterName 'VMware Network Adapter VMnet1' -OutputPath $relativeTarget | Out-Null }
        catch { $blocked = $true }
        if (-not $blocked -or (Test-Path -LiteralPath $relativeTarget)) {
            throw 'Collector accepted a relative evidence destination'
        }
    }
    finally { Remove-Item -LiteralPath $relativeTarget -Force -ErrorAction SilentlyContinue }
    Write-Output 'Mocked Windows host adapter snapshot smoke passed; no VMware tested.'
}
finally { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
