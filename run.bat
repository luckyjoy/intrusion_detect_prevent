@echo off
:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    :: Relaunch as admin using mshta
    echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "%~f0", "", "", "runas", 1 > "%temp%\elevate.vbs"
    "%temp%\elevate.vbs"
    del "%temp%\elevate.vbs"
    exit /b
)

:: Run Python scripts from current directory
cd /d "%~dp0"

start "Real-time Home IDPS"  python idps_engine.py