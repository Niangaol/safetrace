@echo off
cd /d E:\code\ai-threat-intel-demo-v1\web
echo ============================================
echo   SafeTrace Demo - starting...
echo   URL: http://localhost:5180/
echo   Press Ctrl+C to stop
echo ============================================
echo.
npx vite --port 5180 --host
