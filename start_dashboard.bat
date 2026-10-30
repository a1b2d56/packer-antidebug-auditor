@echo off
cd /d "%~dp0"
title Packer ^& Anti-Debug Auditor - Dashboard Launcher

where python >nul 2>nul
if errorlevel 1 (
    echo [!] Python was not found on PATH. Install Python 3.9+ and run: pip install -r requirements.txt
    pause
    exit /b 1
)
where npm >nul 2>nul
if errorlevel 1 (
    echo [!] npm was not found on PATH. Install Node.js 20+ to run the dashboard.
    pause
    exit /b 1
)

if not exist "web\node_modules" (
    echo Installing dashboard dependencies ^(first run^)...
    pushd web
    call npm install
    if errorlevel 1 (
        popd
        echo [!] npm install failed.
        pause
        exit /b 1
    )
    popd
)

echo Starting Packer ^& Anti-Debug Auditor Backend (FastAPI)...
start "Auditor Backend" cmd /k "python -m uvicorn server.main:app --host 127.0.0.1 --port 8000"

echo Starting Packer ^& Anti-Debug Auditor Frontend (Vite)...
start "Auditor Frontend" /d "%~dp0web" cmd /k "npm run dev"

echo.
echo Application is launching!
echo Backend API available at: http://127.0.0.1:8000  (docs: http://127.0.0.1:8000/docs)
echo Frontend Dashboard available at: http://localhost:5173
echo.
pause
