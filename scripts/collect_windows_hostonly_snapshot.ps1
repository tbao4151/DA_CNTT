# Read-only host adapter metadata snapshot. No network traffic, firewall edits,
# VM changes, guest inspection, or automatic Host-only isolation assertion.
param(
    [Parameter(Mandatory = $true)][string]$AdapterName,
    [Parameter(Mandatory = $true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
# Validate the output destination before querying any network configuration.
# This is a privacy boundary for ordinary paths, not an isolation attestation.
$parent = Split-Path -Parent $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath) -or
    -not $parent -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Use an absolute private output path in an existing directory.'
}
$resolvedParent = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $parent).ProviderPath)
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repoPrefix = $repoRoot.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
$parentPath = $resolvedParent.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
if ($parentPath.Equals($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
    $parentPath.StartsWith($repoPrefix + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Host evidence must be stored outside the Git repository.'
}
if (Test-Path -LiteralPath $OutputPath) {
    throw 'Refusing to overwrite an existing evidence snapshot.'
}
$adapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop
$ipv4 = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop |
    ForEach-Object { @{ address = [string]$_.IPAddress; prefix_length = [int]$_.PrefixLength } })
$ipv6 = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction Stop |
    ForEach-Object { [string]$_.IPAddress })
$defaultRoutes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |
    ForEach-Object { [string]$_.NextHop })
$defaultRoutesIpv6 = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction Stop |
    Where-Object { $_.DestinationPrefix -eq '::/0' } |
    ForEach-Object { [string]$_.NextHop })
$dnsInfo = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
$dnsInfoIpv6 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction Stop
$dnsServers = @($dnsInfo.ServerAddresses | ForEach-Object { [string]$_ })
$dnsServersIpv6 = @($dnsInfoIpv6.ServerAddresses | ForEach-Object { [string]$_ })
$snapshot = @{
    schema_version = 2
    capture_origin = 'windows_host_network_configuration'
    adapter_name = [string]$adapter.Name
    adapter_status = [string]$adapter.Status
    adapter_ipv4 = $ipv4
    adapter_ipv6 = $ipv6
    adapter_default_routes = $defaultRoutes
    adapter_default_routes_ipv6 = $defaultRoutesIpv6
    adapter_dns_servers = $dnsServers
    adapter_dns_servers_ipv6 = $dnsServersIpv6
}
$jsonBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($snapshot | ConvertTo-Json -Depth 5))
# CreateNew is atomic: never overwrite original evidence even if the path
# appears between the initial check and this write.
$stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
try { $stream.Write($jsonBytes, 0, $jsonBytes.Length) }
finally { $stream.Dispose() }
Write-Output 'Host adapter metadata captured; VMware guest isolation NOT verified.'
Write-Output 'SHA256:'
(Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
