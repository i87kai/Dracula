@echo off
:: Automatic execution script triggered on Windows boot

timeout /t 2 >nul

:: Search for target_sample.exe across drives E, D, F
set TARGET=""
if exist "E:\target_sample.exe" set TARGET="E:\target_sample.exe"
if exist "D:\target_sample.exe" set TARGET="D:\target_sample.exe"
if exist "F:\target_sample.exe" set TARGET="F:\target_sample.exe"

if not %TARGET%=="" (
    echo [+] Auto-executing target binary under GuestAgent: %TARGET%
    "C:\Sandbox\GuestAgent.exe" %TARGET% --host-ip 10.0.2.2 --host-port 8899
)
