@echo off
title QEMU WINDOWS 10 ANALYSIS LAB
color 0a

echo ==============================================================================
echo                 STARTING QEMU WINDOWS 10 ANALYSIS LAB                         
echo ==============================================================================
echo [*] Disk Image: D:\VirtualMachines\win10.vdi
echo [*] Tools Drive: Attached (guest_share)
echo [*] UEFI Firmware: EDK2 x86_64 NVRAM (pflash code + vars)
echo [*] Accelerators: WHPX / TCG enabled
echo ==============================================================================

"C:\Program Files\qemu\qemu-system-x86_64.exe" ^
  -M q35,accel=whpx:tcg ^
  -cpu qemu64 ^
  -m 4G ^
  -smp 2 ^
  -drive if=pflash,format=raw,unit=0,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ^
  -drive if=pflash,format=raw,unit=1,file="D:\VirtualMachines\uefi_vars.fd" ^
  -drive file="D:\VirtualMachines\win10.vdi",format=vdi,if=virtio ^
  -drive file=fat:rw:guest_share,format=raw ^
  -net user,hostfwd=tcp::8899-:8899 -net nic,model=virtio ^
  -device usb-ehci,id=ehci -device usb-tablet ^
  -vga std

echo [!] QEMU Session Finished.
pause
