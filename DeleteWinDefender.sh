#!/bin/bash

echo "Deleting Windows Defender..."
rm -rf "Windows/System32/SecurityHealthSystray.exe"
rm -rf "Windows/System32/SecurityHealthService.exe"
rm -rf "Windows/System32/SecurityHealthAgent.dll"
rm -rf "Program Files (x86)/Windows Defender"
rm -rf "Program Files/Windows Defender"
rm -rf "Program Files/Windows Defender Advanced Threat Protection"
rm -rf "ProgramData/Microsoft/Windows Defender"
rm -rf "ProgramData/Microsoft/Windows Defender Advanced Threat Protection"
echo "Done! You may now reboot into Windows"
