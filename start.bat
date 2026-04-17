@echo off
title PhishSim - Phishing Simulator

echo.
echo ==========================================
echo   PhishSim -- Phishing Simulator
echo ==========================================
echo.

set ROOT=%~dp0

:: ── Check Python ──────────────────────────
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found.
    echo Please install Python 3.10+ from https://python.org/downloads
    echo Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo Found: %%v

:: ── Install dependencies ──────────────────
echo.
echo [1/2] Installing Python dependencies...
cd /d "%ROOT%backend"
pip install fastapi "uvicorn[standard]" sqlalchemy pydantic python-multipart aiofiles apscheduler openpyxl
if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: pip install failed.
    echo Try opening a new Command Prompt and running:
    echo   python -m pip install --upgrade pip
    pause
    exit /b 1
)

:: ── Start server ──────────────────────────
echo.
echo [2/2] Starting PhishSim server...
echo.
echo ==========================================
echo   Open your browser and go to:
echo.
echo   http://localhost:8000
echo.
echo   API Docs: http://localhost:8000/docs
echo.
echo   Press Ctrl+C to stop.
echo ==========================================
echo.

python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
