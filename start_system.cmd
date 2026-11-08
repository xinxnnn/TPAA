@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start_system.ps1" %*
if errorlevel 1 (
    echo.
    echo System startup failed. Review the error above and logs under the configured state root.
    pause
    exit /b 1
)
exit /b 0
