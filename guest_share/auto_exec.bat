@echo off
:: Automatic execution script triggered on Windows boot inside the sandbox guest.
::
:: The host picks its telemetry port at runtime and may not get the configured
:: one, so it writes dracula_session.ini onto this shared drive before QEMU
:: starts. This script reads the port from there and passes it to GuestAgent.
:: If the file is missing for any reason, it falls back to the historical
:: default so an older host still works.

timeout /t 2 >nul

set TARGET=
set SESSION=
set HOST_IP=10.0.2.2
set HOST_PORT=8899

:: Locate the shared drive by looking for the staged sample on each candidate.
for %%D in (E D F G) do (
    if exist "%%D:\target_sample.exe" (
        if not defined TARGET set TARGET=%%D:\target_sample.exe
        if exist "%%D:\dracula_session.ini" (
            if not defined SESSION set SESSION=%%D:\dracula_session.ini
        )
    )
)

:: The session file may live on a share that carries no sample, so look again.
if not defined SESSION (
    for %%D in (E D F G) do (
        if exist "%%D:\dracula_session.ini" (
            if not defined SESSION set SESSION=%%D:\dracula_session.ini
        )
    )
)

if defined SESSION (
    echo [+] Reading host session handoff from %SESSION%
    for /f "usebackq tokens=1,2 delims== " %%A in ("%SESSION%") do (
        if /i "%%A"=="host_port" set HOST_PORT=%%B
        if /i "%%A"=="host_ip" set HOST_IP=%%B
    )
) else (
    echo [!] No session handoff found; falling back to %HOST_IP%:%HOST_PORT%
)

if not defined TARGET (
    echo [!] No target_sample.exe found on any shared drive. Nothing to run.
    exit /b 1
)

echo [+] Auto-executing target binary under GuestAgent: %TARGET%
echo [+] Telemetry host: %HOST_IP%:%HOST_PORT%
"C:\Sandbox\GuestAgent.exe" "%TARGET%" --host-ip %HOST_IP% --host-port %HOST_PORT%
