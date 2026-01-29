@echo off
title AnonIT Server
echo ========================================
echo        AnonIT Secure Messenger Server
echo ========================================
echo.

:: Check if venv exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    echo Installing dependencies...
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)

echo.
echo Starting server on port 8765...
echo Press Ctrl+C to stop
echo.

:loop
python server.py
echo.
echo Server stopped. Restarting in 5 seconds...
echo Press Ctrl+C again to exit completely
timeout /t 5 /nobreak >nul
goto loop
