@echo off
rem Drag and drop a Veeam log bundle (.zip) or an extracted folder on this file.
rem Uses PowerShell 7 (pwsh) if installed, otherwise Windows PowerShell 5.1.
setlocal
if "%~1"=="" (
    echo Usage: drag a Veeam log bundle .zip ^(or folder^) onto this file, or:
    echo        %~nx0 "C:\path\to\VeeamBackupLogs.zip"
    pause
    exit /b 1
)
where pwsh >nul 2>nul
if %errorlevel%==0 (set "PS=pwsh") else (set "PS=powershell")
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-VeeamLogAnonymizer.ps1" -InputPath "%~1"
echo.
pause
