# CleanW11

### Description
Various tweaks and modifications to clean up Windows and improve performance without removing any default functionality (excluding Xbox and Cortana). I've tried to avoid making any aesthetic changes, it should still feel like normal Windows 11, just better. Use at your own risk, all functions are experimental.

### Install instructions
1. Download the latest official ISO using [UUP dump](https://uupdump.net/fetchupd.php?arch=amd64&ring=wif&build=latest) - current version as of writing is 10.0.22000.100
2. Use Rufus (or similar) to make a bootable USB drive using the ISO, then boot from the USB drive and install Windows as per normal
4. Run Windows update, reboot, and repeat until there are no updates
5. Install latest GPU drivers and any other drivers that are not automatically installed by Windows update
6. Right click `CleanW11.ps1` and run it in Powershell
7. Reboot, enjoy Windows 11

### Optional: Remove Windows Defender
Not recommended unless you really know what you're doing. Use at your own risk - this is not reversable.
1. Place `DeleteWinDefender.sh` into the root of your Windows drive (ie. C:\)
2. Boot from an external Linux OS (ie. Ubuntu on a USB drive)
3. Navigate to your Windows drive
4. Execute `DeleteWinDefender.sh` with elevated privilege (ie. `sudo ./DeleteWinDefender.sh`)
5. Boot back into Windows
