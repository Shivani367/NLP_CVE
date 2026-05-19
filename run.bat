@echo off
title CVE NLP Threat Intelligence Dashboard Launcher
color 0B

echo ==============================================================================
echo       ___  _  _ ___  ____ ____    _ _  _ ___ ____ _       ____ _  _ ____
echo       ^|__] ^|_^|  ^|__] ^|___ ^|__/    ^| ^|\^|  ^|  ^|___ ^|       ^|___ ^|\^|^| ^| __
echo       ^|__]  ^|   ^|__] ^|___ ^|  \    ^| ^| \  ^|  ^|___ ^|___    ^|___ ^| \^| ^|__^|
echo ==============================================================================
echo.
echo [+] Initializing local environments...

:: 1. Check and activate local virtual environment 'cve'
if exist "cve\Scripts\activate.bat" (
    echo [+] Local python virtual environment (cve) detected. Activating...
    call cve\Scripts\activate.bat
) else (
    echo [!] Local virtual environment 'cve' not found. Using system Python.
)

:: 2. Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [X] ERROR: Python is not installed or not in your system PATH!
    echo Please install Python 3.10+ and try again.
    pause
    exit /b
)

echo [+] Python environment verified:
python --version

:: 3. Install/verify dependencies
echo [+] Validating package dependencies in requirements.txt...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] WARNING: Problem encountered installing packages. The server will still attempt to launch.
)

:: 4. Start web browser in 3 seconds in the background
echo [+] Triggering dashboard in browser...
start http://localhost:8000

:: 5. Launch FastAPI server
echo [+] Starting local FastAPI server on http://localhost:8000...
echo [+] Press Ctrl+C in this terminal window to stop the server.
echo ==============================================================================
echo.

python main.py

pause
