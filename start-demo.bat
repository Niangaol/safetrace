@echo off
chcp 65001 >nul 2>&1
setlocal
set "DEMO_DIR=E:\code\ai-threat-intel-demo-v1"
set "PORT=5180"

echo ============================================
echo   SafeTrace Demo  (最新版: -demo-v1)
echo   URL: http://localhost:%PORT%/
echo ============================================
echo.

rem ── 1) 清掉占着端口的旧实例 ──────────────────────────────
rem 否则浏览器打开的会是**上一个目录**起的服务（本机曾同时存在 -demo 与 -demo-v1，
rem 旧实例占着 5180，看起来"改了没生效"）。
set "KILLED="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do (
    echo [清理] 端口 %PORT% 被 PID %%p 占用，正在结束...
    taskkill /PID %%p /F >nul 2>&1
    set "KILLED=1"
)
if defined KILLED (
    rem 给 Windows 一点时间真正释放端口
    ping -n 3 127.0.0.1 >nul 2>&1
)

rem ── 2) 进最新目录 ────────────────────────────────────────
cd /d "%DEMO_DIR%\web" || (
    echo [错误] 找不到 %DEMO_DIR%\web
    pause
    exit /b 1
)

if not exist "node_modules" (
    echo [安装] 首次运行，安装前端依赖...
    call npm install
    echo.
)

rem ── 3) 提示后端 ─────────────────────────────────────────
rem 前端默认"先连真实后端"（api.ts 的 auto 模式）。后端没起时会自动回退到预置数据
rem 并在页面顶部标注「预置数据」——这是诚实降级，不是故障。
rem 想要真实数据，另开一个窗口起后端：
rem   cd /d %DEMO_DIR%
rem   set PYTHONPATH=%DEMO_DIR%\src
rem   set POSTGRES_DSN=sqlite:///%DEMO_DIR:\=/%/data/demo.db
rem   python -m uvicorn aiintel.api.main:app --host 127.0.0.1 --port 8000
echo [提示] 后端未启动时页面会显示「预置数据」横幅；启动后端(:8000)后自动转为真实数据。
echo.

call npx vite --port %PORT% --host
pause
