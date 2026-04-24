@echo off
title BGP Detector - Force Stop
color 0C

echo.
echo  ========================================
echo   BGP Detector - Force Stop
echo  ========================================
echo.

echo [*] Killing Python processes...
taskkill /F /IM python.exe /T >nul 2>&1

if errorlevel 1 (
    echo [!] No Python processes found running.
) else (
    echo [OK] Stopped.
)

echo [*] Releasing port 8000 if still bound...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
    echo [OK] Killed PID %%a on port 8000
)

echo.
echo [*] Done.
pause