@echo off
REM ============================================================
REM  PhishGuard - One-command server launcher (Windows)
REM  Kills any stale server on :8000, frees the port, then starts
REM  a single clean backend. Logs are written by the app itself to
REM  backend\phishguard-server.log (no shell redirection, so no
REM  double-open file lock).
REM ============================================================
setlocal
cd /d "%~dp0"

set LOG=backend\phishguard-server.log
set PY=python

echo [PhishGuard] Stopping any stale server on port 8000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 2 /nobreak >nul

if not exist backend mkdir backend
if not exist %LOG% type nul > %LOG%

echo [PhishGuard] Starting backend...
start "" /min python run_server.py

timeout /t 8 /nobreak >nul
echo [PhishGuard] Started. Health check:
powershell -NoProfile -Command "try { (Invoke-WebRequest -Uri 'http://127.0.0.1:8000/health' -UseBasicParsing -TimeoutSec 5).StatusCode } catch { 'NOT RUNNING' }"
echo.
echo [PhishGuard] Live log:  Get-Content "backend\phishguard-server.log" -Wait
endlocal
