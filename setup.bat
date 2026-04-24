@echo off
title BGP Detector - Setup
color 0A

echo.
echo  ========================================
echo   BGP Hijack Detector - First-Time Setup
echo  ========================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

echo [*] Python found:
python --version

:: Create venv if it doesn't exist
if not exist "venv\" (
    echo [*] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment already exists.
)

:: Activate and install
echo [*] Installing dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip -q
pip install -r requirements.txt

if errorlevel 1 (
    echo [ERROR] Dependency installation failed. Check requirements.txt.
    pause
    exit /b 1
)

echo.
echo  ========================================
echo   Setup complete!
echo   Run  run.bat  to start the detector.
echo  ========================================
echo.
pause