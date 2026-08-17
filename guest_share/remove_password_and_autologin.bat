@echo off
title REMOVE PASSWORD AND ENABLE AUTOLOGON
color 0e

echo ==============================================================================
echo              REMOVING WINDOWS PASSWORD & ENABLING INSTANT AUTOLOGON           
echo ==============================================================================

:: 1. Remove password for current user and administrator
echo [+] Clearing user password...
net user "%USERNAME%" ""
net user Administrator "" >nul 2>&1
net user User "" >nul 2>&1

:: 2. Configure Windows AutoAdminLogon in Registry (No login screen, instant boot)
echo [+] Enabling AutoAdminLogon in Registry...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d "%USERNAME%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ForceAutoLogon /t REG_SZ /d "1" /f >nul 2>&1

:: 3. Disable Windows Lock Screen and Screensaver
echo [+] Disabling Lock Screen and Sleep...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f >nul 2>&1
powercfg -change -standby-timeout-ac 0 >nul 2>&1
powercfg -change -monitor-timeout-ac 0 >nul 2>&1

echo ==============================================================================
echo [SUCCESS] Password removed! Windows will now boot instantly to Desktop!
echo ==============================================================================
timeout /t 4
