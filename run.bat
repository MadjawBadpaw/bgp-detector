@echo off
title BGP Hijack Detector
color 0A

echo.
echo  ========================================
echo   BGP Hijack Detector
echo   Dashboard → http://127.0.0.1:8000
echo   Press Ctrl+C to stop
echo  ========================================
echo.

:: Check venv exists
if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found.
    echo         Run setup.bat first.
    pause
    exit /b 1
)

:: Check main.py exists
if not exist "main.py" (
    echo [ERROR] main.py not found. Are you in the right folder?
    pause
    exit /b 1
)

call venv\Scripts\activate.bat
python main.py

echo.
echo [*] Detector stopped.
pause