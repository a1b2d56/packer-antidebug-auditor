@echo off
chcp 65001 >nul
title Packer & Anti-Debug Auditor Demo
cd /d "%~dp0"
cls

python run_demo.py %*
if errorlevel 1 (
    echo.
    echo [ERROR] Demo exited with an error. Check Python environment.
    echo.
)

pause
