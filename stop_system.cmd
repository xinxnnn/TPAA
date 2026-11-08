@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stop_system.ps1" %*
if errorlevel 1 (
    echo.
    echo System shutdown reported an error.
    pause
    exit /b 1
)
echo TPAA local platform shutdown command completed.
pause
exit /b 0
