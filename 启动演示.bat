@echo off
cd /d E:\code\ai-threat-intel-demo-v1\web
echo ============================================
echo   SafeTrace Demo - 启动中...
echo   地址: http://localhost:5180/
echo   按 Ctrl+C 停止
echo ============================================
echo.
npx vite --port 5180 --host
