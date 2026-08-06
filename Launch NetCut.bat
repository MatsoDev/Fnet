@echo off
title NetCut Pro
cd /d "%~dp0"

echo Starting NetCut Pro Web UI...
echo Waiting for server to become ready... (scan runs in background)
echo.

:: Start Flask server in background
start /B python app.py

:: Poll until the Flask server answers, then open the browser right away
set tries=0
:waitloop
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 http://127.0.0.1:5000/api/info; exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    set /a tries+=1
    if %tries% geq 60 (
        echo Server did not become ready in time.
        exit /b 1
    )
    timeout /t 1 /nobreak >nul
    goto waitloop
)
start http://127.0.0.1:5000
exit
