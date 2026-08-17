@echo off
title SANDBOX LAB AUTOMATED SETUP
color 0b

echo ==============================================================================
echo              CONFIGURING AUTOMATED ANALYSIS & REVERSE LAB                      
echo ==============================================================================

:: 1. Remove password and enable instant AutoAdminLogon
echo [+] Clearing Windows Password & Enabling AutoAdminLogon...
net user "%USERNAME%" "" >nul 2>&1
net user Administrator "" >nul 2>&1
net user User "" >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d "%USERNAME%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ForceAutoLogon /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f >nul 2>&1

:: 2. Create Target Directory
if not exist "C:\Sandbox" mkdir "C:\Sandbox"
if not exist "C:\Sandbox\Tools" mkdir "C:\Sandbox\Tools"

:: 2. Determine Drive Letter where this script is running
set SCRIPT_DIR=%~dp0

echo [+] Copying C++ Runtime DLLs to System32 and C:\Sandbox...
copy /Y "%SCRIPT_DIR%*.dll" "C:\Windows\System32\" >nul 2>&1
copy /Y "%SCRIPT_DIR%*.dll" "C:\Sandbox\" >nul 2>&1

echo [+] Copying GuestAgent to C:\Sandbox\GuestAgent.exe...
copy /Y "%SCRIPT_DIR%GuestAgent.exe" "C:\Sandbox\GuestAgent.exe"

echo [+] Deploying Analysis Tools to C:\Sandbox\Tools...
xcopy /E /I /Y "%SCRIPT_DIR%tools" "C:\Sandbox\Tools"

:: 3. Accept Sysinternals EULA in Registry
echo [+] Setting Sysinternals EulaAccepted in Registry...
reg add "HKCU\Software\Sysinternals\Process Monitor" /v EulaAccepted /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Sysinternals\Process Explorer" /v EulaAccepted /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Sysinternals\TCPView" /v EulaAccepted /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Sysinternals\Autoruns" /v EulaAccepted /t REG_DWORD /d 1 /f >nul 2>&1

echo [+] Setting up Windows Startup Autorun for GuestAgent...
copy /Y "%SCRIPT_DIR%auto_exec.bat" "C:\Sandbox\auto_exec.bat" >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SandboxAutoExec" /f >nul 2>&1

:: Place only in Startup folder
set STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
copy /Y "%SCRIPT_DIR%auto_exec.bat" "%STARTUP%\auto_exec.bat" >nul 2>&1

:: 5. Create Desktop Shortcuts for Analysts
echo [+] Creating Desktop Shortcuts...
set DESKTOP=%USERPROFILE%\Desktop
copy /Y "%SCRIPT_DIR%GuestAgent.exe" "%DESKTOP%\GuestAgent.exe" >nul 2>&1

echo ==============================================================================
echo [SUCCESS] Sandbox Analysis Lab is 100%% Configured and Ready!
echo ==============================================================================
timeout /t 5
