@echo off
title Advanced IDS - Project Launcher
color 0A

echo ==========================================
echo       ADVANCED NETWORK IDS
echo       Starting Project...
echo ==========================================
echo.

cd /d "%~dp0"

echo [1/3] Starting Backend...
start "Advanced IDS - Backend" cmd /k "cd /d %~dp0backend && call venv\Scripts\activate.bat && python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"

timeout /t 5 /nobreak >nul

echo [2/3] Starting Frontend...
start "Advanced IDS - Frontend" cmd /k "cd /d %~dp0frontend && npm.cmd run dev"

timeout /t 8 /nobreak >nul

echo [3/3] Opening Application...
start "" "http://localhost:3000"

echo.
echo ==========================================
echo Project started successfully.
echo Backend:  http://127.0.0.1:8000
echo API Docs: http://127.0.0.1:8000/api/v1/docs
echo Frontend: http://localhost:3000
echo ==========================================
echo.
pause