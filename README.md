# CleanW11

### Description
Various tweaks and modifications to clean up Windows and improve performance without removing any default functionality (excluding Xbox and Cortana). I've tried to avoid making any aesthetic changes aside from changing to dark mode, it should still feel like normal Windows 11, just better. Use at your own risk, all functions are experimental.

### Making the Windows 11 installer
1. Go to [UUP dump](https://uupdump.net/), this allows you to download the offical ISO directly from Microsoft servers
1. Go to latest dev channel build and click on the newest version of Windows 11 (10.0.22000.100 at time of writing)
1. Select your preferred language, click `Next`
1. Deselect all editions except `Windows Pro`, click `Next`
1. Select `Download and convert to ISO`, tick only `Include updates`, click `Create download package`
1. Extract all files from the downloaded `.zip`, and run the `.cmd` file to download the ISO
1. Use [Rufus](https://rufus.ie/en/) to make a bootable USB drive using the ISO, just use default settings

### Install instructions
1. Boot from the USB drive and install Windows as per normal
1. Run Windows update, reboot, and repeat until there are no updates left
1. Install the latest GPU drivers and any other drivers you need that are not automatically installed by Windows update
1. Right click `CleanW11.ps1` and run it in Powershell
1. Reboot, enjoy Windows 11

### Optional: Remove Windows Defender
Not recommended unless you really know what you're doing. Normal methods of disabling Windows Defender used for Windows 10 have proven ineffective, so this script simply deletes it from the OS. Use at your own risk - this is obviously not reversable.
1. Place `DeleteWinDefender.sh` into the root of your Windows drive (ie. `C:\`)
1. Boot from an external Linux OS (ie. [Ubuntu on a USB drive](https://ubuntu.com/tutorials/try-ubuntu-before-you-install))
1. Navigate to your Windows drive
1. Execute `DeleteWinDefender.sh` with elevated privilege (ie. `sudo ./DeleteWinDefender.sh`)
1. Boot back into Windows
