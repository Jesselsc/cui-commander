@echo off
setlocal

set LAUNCHER_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%LAUNCHER_DIR%..\bootstrap\setup_and_run_fleet_commander.ps1"

echo.
pause
