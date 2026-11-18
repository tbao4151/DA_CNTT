# Start DA005 FastAPI Backend on http://127.0.0.1:8000
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    $ParentVenv = Join-Path (Split-Path -Parent $RepoRoot) ".venv\Scripts\python.exe"
    if (Test-Path $ParentVenv) {
        $VenvPython = $ParentVenv
    } else {
        $VenvPython = "python"
    }
}

Write-Host "Starting DA005 FastAPI Backend at http://127.0.0.1:8000 ..." -ForegroundColor Cyan
$env:PYTHONPATH = Join-Path $RepoRoot "src"
& $VenvPython -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
