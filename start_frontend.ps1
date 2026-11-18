# Start DA005 Next.js Frontend on http://127.0.0.1:3000
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$FrontendDir = Join-Path $RepoRoot "frontend"
Set-Location $FrontendDir

if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
    Write-Host "Installing frontend dependencies (npm.cmd install)..." -ForegroundColor Yellow
    & npm.cmd install
}

if (-not $env:NEXT_PUBLIC_API_BASE_URL) {
    $env:NEXT_PUBLIC_API_BASE_URL = "http://127.0.0.1:8000/api/v1"
}

Write-Host "Starting DA005 Next.js Frontend at http://127.0.0.1:3000 ..." -ForegroundColor Cyan
& npm.cmd run dev
