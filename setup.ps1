#!/usr/bin/env pwsh
<#
.SYNOPSIS
    One-shot setup for the JWT Auth Service.
    Run this script once after cloning to create the virtualenv, install deps,
    and copy the .env template.

.USAGE
    cd auth-service
    .\setup.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n==> Checking for Python..." -ForegroundColor Cyan
$pythonCmd = $null
foreach ($candidate in @("python", "python3", "py")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $ver = & $candidate --version 2>&1
        if ($ver -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 10) {
                $pythonCmd = $candidate
                Write-Host "    Found: $ver ($candidate)" -ForegroundColor Green
                break
            }
        }
    }
}

if (-not $pythonCmd) {
    Write-Host ""
    Write-Host "    ERROR: Python 3.10+ not found on PATH." -ForegroundColor Red
    Write-Host ""
    Write-Host "    Please install Python from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "    (tick 'Add Python to PATH' during installation), then re-run this script." -ForegroundColor Red
    exit 1
}

Write-Host "`n==> Creating virtual environment (.venv)..." -ForegroundColor Cyan
& $pythonCmd -m venv .venv

Write-Host "`n==> Activating virtual environment..." -ForegroundColor Cyan
$activateScript = Join-Path $PSScriptRoot ".venv\Scripts\Activate.ps1"
. $activateScript

Write-Host "`n==> Installing dependencies..." -ForegroundColor Cyan
pip install --upgrade pip --quiet
pip install -r requirements.txt

Write-Host "`n==> Setting up .env..." -ForegroundColor Cyan
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    # Generate a random SECRET_KEY and inject it
    $key = & python -c "import secrets; print(secrets.token_hex(32))"
    (Get-Content ".env") -replace "CHANGE_ME_generate_a_real_secret_key", $key | Set-Content ".env"
    Write-Host "    .env created with a random SECRET_KEY." -ForegroundColor Green
} else {
    Write-Host "    .env already exists - skipping." -ForegroundColor Yellow
}

Write-Host "`n==> Running test suite..." -ForegroundColor Cyan
pytest -v

Write-Host ""
Write-Host "==> Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To start the dev server:" -ForegroundColor Green
Write-Host "    .venv\Scripts\Activate.ps1" -ForegroundColor Green
Write-Host "    uvicorn app.main:app --reload" -ForegroundColor Green
Write-Host ""
Write-Host "Then visit:" -ForegroundColor Green
Write-Host "    http://localhost:8000/docs   (Swagger UI)" -ForegroundColor Green
Write-Host "    http://localhost:8000/redoc  (ReDoc)" -ForegroundColor Green