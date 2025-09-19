@echo off

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

setlocal enabledelayedexpansion

echo.
echo === Extracting blocked IPs from firewall rules ===

set "ipList=%TEMP%\fw_all_ips.txt"
set "dupeList=%TEMP%\fw_dupe_ips.txt"
set "sortedList=%TEMP%\fw_sorted_ips.txt"
set "foundRules=%TEMP%\fw_found_rules.txt"

del "%ipList%" "%dupeList%" "%sortedList%" "%foundRules%" >nul 2>&1

:: Extract all rules with RemoteIP and collect IPs
for /f "tokens=*" %%A in ('netsh advfirewall firewall show rule name=all ^| findstr /I "RemoteIP"') do (
    echo %%A | findstr /R "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" >> "%ipList%"
)

:: Normalize IPs
for /f "tokens=2 delims=:" %%B in ('type "%ipList%"') do (
    echo %%B | findstr /R "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" >> "%sortedList%"
)

:: Sort and find duplicates
sort "%sortedList%" > "%sortedList%.tmp"
move /Y "%sortedList%.tmp" "%sortedList%" >nul

set "prevIP="
for /f "tokens=* delims=" %%C in (%sortedList%) do (
    set "currIP=%%C"
    if "!currIP!"=="!prevIP!" (
        echo !currIP!>>"%dupeList%"
    )
    set "prevIP=!currIP!"
)

echo.
echo === Duplicate IPs Found ===
if exist "%dupeList%" (
    type "%dupeList%"
) else (
    echo No duplicate IPs found.
)

:: Remove rules with duplicate IPs
echo.
echo === Removing rules with duplicate IPs ===
if exist "%dupeList%" (
    for /f "tokens=* delims=" %%D in (%dupeList%) do (
        echo Searching for rules blocking IP: %%D
        netsh advfirewall firewall show rule name=all | findstr /C:"RemoteIP: %%D" > "%foundRules%"
        for /f "tokens=*" %%R in (%foundRules%) do (
            for /f "tokens=2 delims=:" %%N in ("%%R") do (
                set "ruleName=%%N"
                set "ruleName=!ruleName:~1!"
                echo Deleting rule: !ruleName!
                netsh advfirewall firewall delete rule name="!ruleName!" >nul
            )
        )
    )
)

:: Delete rules matching IDPS_Block_192.168.1.xx
echo.
echo === Deleting rules matching IDPS_Block_192.168.1.xx ===
for /L %%i in (1,1,254) do (
    set "ruleName=IDPS_Block_192.168.1.%%i"
    netsh advfirewall firewall show rule name="!ruleName!" >nul 2>&1
    if !errorlevel! NEQ 1 (
        echo Deleting rule: !ruleName!
        netsh advfirewall firewall delete rule name="!ruleName!" >nul
    )
)

echo.
echo === Cleanup complete ===
pause
