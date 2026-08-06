@echo off
title NetCut Pro
cd /d "%~dp0"

echo Starting NetCut Pro Web UI...
echo Opening browser once server is ready...
echo.

:: Start Flask server in background
start /B python app.py

:: Wait for server and open browser
timeout /t 4 /nobreak >nul
start http://127.0.0.1:5000
exit
