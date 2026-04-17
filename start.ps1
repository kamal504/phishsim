# ─────────────────────────────────────────────────────────────
#  PhishSim — PowerShell Start Script (Windows, Python only)
#  Run with:  .\start.ps1
#  If blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
# ─────────────────────────────────────────────────────────────

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   PhishSim -- Phishing Simulator" -ForegroundColor Cyan
Write-Host "   (Python only - no Node.js needed)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ── Check Python ───────────────────────────────────────────────
try { $pv = python --version 2>&1; Write-Host "Python found: $pv" -ForegroundColor Green }
catch {
    Write-Host "ERROR: Python not found." -ForegroundColor Red
    Write-Host "Install from https://python.org/downloads" -ForegroundColor Yellow
    Write-Host "Make sure to check 'Add Python to PATH' during install." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"; exit 1
}

# ── Install dependencies ──────────────────────────────────────
Write-Host ""
Write-Host "[1/2] Installing Python dependencies..." -ForegroundColor Yellow
Set-Location "$Root\backend"
pip install fastapi uvicorn sqlalchemy pydantic python-multipart aiofiles -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: pip install failed." -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}

# ── Start server ───────────────────────────────────────────────
Write-Host ""
Write-Host "[2/2] Starting PhishSim server..." -ForegroundColor Yellow
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "   App is running!" -ForegroundColor Green
Write-Host ""
Write-Host "   Open in browser: http://localhost:8000" -ForegroundColor White
Write-Host "   API Docs:        http://localhost:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "   Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
