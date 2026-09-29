@echo off
setlocal
set "DEMO_DIR=E:\code\ai-threat-intel-demo-v1"
set "PORT=5180"

echo ============================================
echo   SafeTrace Demo  (latest: -demo-v1)
echo   URL: http://localhost:%PORT%/
echo ============================================
echo.

rem -- 1) Kill whatever already holds the port -------------------
rem Otherwise the browser opens a server started from an OLD directory
rem (both -demo and -demo-v1 have existed on this machine; the stale one
rem held 5180, which looked like "my change did not take effect").
rem
rem NOTE: this file is deliberately ASCII-only.
rem A .bat file's *body* is parsed with the system ANSI codepage, NOT with the
rem codepage set by `chcp`. So non-ASCII text here is a portability hazard:
rem with UTF-8 it mojibakes, and mixing it with `chcp 65001` corrupts compound
rem statements (seen in practice as bogus "is not recognized as an internal
rem or external command" errors). Keep this file ASCII.
set "KILLED="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do (
    echo [cleanup] port %PORT% held by PID %%p, killing...
    taskkill /PID %%p /F >nul 2>&1
    set "KILLED=1"
)
if defined KILLED (
    rem give Windows a moment to actually release the port
    ping -n 3 127.0.0.1 >nul 2>&1
)

rem -- 2) Enter the latest directory -----------------------------
cd /d "%DEMO_DIR%\web" || (
    echo [error] not found: %DEMO_DIR%\web
    pause
    exit /b 1
)

if not exist "node_modules" (
    echo [setup] first run, installing frontend deps...
    call npm install
    echo.
)

rem -- 3) Backend hint -------------------------------------------
rem The frontend tries the real backend first (api.ts "auto" mode). If the
rem backend is down it falls back to preset data and shows a banner saying so.
rem That is an explicit degradation, not a failure.
rem To get live data, start the backend in another window:
rem   cd /d %DEMO_DIR%
rem   set PYTHONPATH=%DEMO_DIR%\src
rem   set POSTGRES_DSN=sqlite:///%DEMO_DIR:\=/%/data/demo.db
rem   python -m uvicorn aiintel.api.main:app --host 127.0.0.1 --port 8000
echo [hint] With no backend on :8000 the page shows a "preset data" banner;
echo        start the backend and it switches to live data automatically.
echo.

call npx vite --port %PORT% --host
pause
