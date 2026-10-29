# Run INSIDE an operator-owned Windows guest. Read-only metadata only.
# This does NOT attest VMware isolation, authorization, or host configuration.
param([Parameter(Mandatory = $true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$parent = Split-Path -Parent $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath) -or
    -not $parent -or -not (Test-Path -LiteralPath $parent -PathType Container) -or
    (Test-Path -LiteralPath $OutputPath)) {
    throw 'Use a new absolute private output file in an existing directory.'
}
$resolvedParent = (Resolve-Path -LiteralPath $parent).ProviderPath
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ($resolvedParent.TrimEnd([char[]]@('\', '/')) -eq $repoRoot.TrimEnd([char[]]@('\', '/')) -or
    $resolvedParent.StartsWith($repoRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Guest evidence must be stored outside the Git repository.'
}
$nics = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
$all4 = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)
$all6 = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop)
$routes4 = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' })
$routes6 = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop |
    Where-Object { $_.DestinationPrefix -eq '::/0' })
$dns4 = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop)
$dns6 = @(Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction Stop)
$adapters = @($nics | ForEach-Object {
    $nic = $_
    @{
        name = [string]$nic.Name
        status = [string]$nic.Status
        if_index = [int]$nic.ifIndex
        ipv4 = @($all4 | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex } |
            ForEach-Object { @{ address = [string]$_.IPAddress; prefix_length = [int]$_.PrefixLength } })
        ipv6 = @($all6 | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex } |
            ForEach-Object { [string]$_.IPAddress })
    }
})
$snapshot = @{
    schema_version = 1
    capture_origin = 'windows_guest_network_configuration'
    adapters = $adapters
    default_routes_ipv4 = @($routes4 | ForEach-Object { "{0}:{1}" -f $_.InterfaceIndex, $_.NextHop })
    default_routes_ipv6 = @($routes6 | ForEach-Object { "{0}:{1}" -f $_.InterfaceIndex, $_.NextHop })
    dns_servers_ipv4 = @($dns4 | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
    dns_servers_ipv6 = @($dns6 | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
}
$bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($snapshot | ConvertTo-Json -Depth 7))
if ($bytes.Length -gt 65536) { throw 'Guest snapshot exceeds the offline verifier size limit.' }
$stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
try { $stream.Write($bytes, 0, $bytes.Length) }
finally { $stream.Dispose() }
Write-Output 'Guest network metadata captured; VMware Host-only isolation NOT verified.'
Write-Output 'SHA256:'
(Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
