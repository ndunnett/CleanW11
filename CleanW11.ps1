# Setup script execution and automatically elevate powershell to admin
$ErrorActionPreference = "SilentlyContinue"
Set-ExecutionPolicy unrestricted
Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue | Out-Null

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script with elevated priveliges. PowerShell will now relaunch as administrator and continue automatically."
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

#========================================
# Global Functions - Start
#========================================

function DisableService {
    param($Name, $Desc)

    if ($null -eq $Desc) {
        Write-Host "Disabling $Name..." -NoNewline
    }
    else {
        Write-Host ("$Desc...") -NoNewline
    }

    $startMode = (Get-WMIObject win32_service -filter "name='$Name'").startmode

    if ($startMode -eq "Disabled") {
        Write-Host " already disabled." -ForegroundColor Yellow
    }
    else {
        Get-Service $Name | Stop-Service -PassThru | Set-Service -StartupType disabled
        Write-Host " done." -ForegroundColor Green
    }
}

function DisableServices($names) {
    foreach ($name in $names) {
        DisableService -Name $name
    }
}

function UninstallAppxPackage($app) {
    Write-Host "Uninstalling $app..." -NoNewline
    $package = Get-AppxPackage -allusers $app

    if ($null -eq $package) {
        Write-Host " not installed." -ForegroundColor Yellow
    }
    else {
        Remove-AppxPackage -allusers $package
        Write-Host " done." -ForegroundColor Green
    }
}

function UninstallAppxPackages($apps) {
    foreach ($app in $apps) {
        UninstallAppxPackage($app)
    }
}

function SetReg {
    param($Path, $Key, $Value, $Desc)

    if ($null -ne $Desc) {
        Write-Host ("$Desc...") -NoNewline
    }

    if ((Get-ItemPropertyValue -Path ("HKLM:" + $Path) -Name $Key) -eq $Value) {
        if ((Get-ItemPropertyValue -Path ("HKCU:" + $Path) -Name $Key) -eq $Value) {
            if ($null -ne $Desc) {
                Write-Host " already set." -ForegroundColor Yellow
            }
            return
        }
    }

    if (!(Test-Path ("HKLM:" + $Path))) {
        New-Item -Path ("HKLM:" + $Path) -Force | out-null
    }

    if (!(Test-Path ("HKCU:" + $Path))) {
        New-Item -Path ("HKCU:" + $Path) -Force | out-null
    }

    Set-ItemProperty -Path ("HKLM:" + $Path) -Name $Key -Value $Value -Force
    Set-ItemProperty -Path ("HKCU:" + $Path) -Name $Key -Value $Value -Force

    if ($null -eq $Desc) {
        return
    }

    if ((Get-ItemPropertyValue -Path ("HKLM:" + $Path) -Name $Key) -eq $Value) {
        if ((Get-ItemPropertyValue -Path ("HKCU:" + $Path) -Name $Key) -eq $Value) {
            Write-Host " done." -ForegroundColor Green
            return
        }
    }

    Write-Host " failed!" -ForegroundColor Red
}

#========================================
# Global Functions - End
#========================================
# Privacy - Start
#========================================

function DisableTelemetry {
    # https://www.neweggbusiness.com/smartbuyer/windows/should-you-disable-windows-10-telemetry/
    Write-Host ""
    Write-Host "Disable data collection through telemetry." -BackgroundColor Black
    Write-Host ""

    Write-Host "Disabling telemetry policies through registry..." -NoNewline
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    )
    foreach ($path in $paths) {
        Set-ItemProperty $path AllowTelemetry -Value 0
    }
    Write-Host " done." -ForegroundColor Green

    Write-Host "Disabling telemetry related scheduled tasks..." -NoNewline
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Autochk\" -TaskName "Proxy" | Out-Null
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "Consolidator" | Out-Null
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\DiskDiagnostic\" -TaskName "Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Feedback\Siuf\" -TaskName "DmClient" | Out-Null
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Feedback\Siuf\" -TaskName "DmClientOnScenarioDownload" | Out-Null
    Write-Host " done." -ForegroundColor Green

    $services = @(
        "DiagTrack"
        "dmwappushservice"
        "wisvc"
        "DsmSvc"
        "EventLog"
    )
    DisableServices($services)
}

function UninstallCortana {
    # https://endurtech.com/how-to-disable-microsofts-cortana/
    Write-Host ""
    Write-Host "Uninstall Cortana." -BackgroundColor Black
    Write-Host ""
    UninstallAppxPackage("Microsoft.549981C3F5F10")
}

function MiscPrivacy {
    Write-Host ""
    Write-Host "Miscellaneous registry changes for privacy purposes." -BackgroundColor Black
    Write-Host ""

    # Privacy & security > General
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Key "Enabled" -Value "0" -Desc "Disabling personalised ads"
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\CPSS\Store\AdvertisingInfo" -Key "Value" -Value "0"
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Key "Start_TrackProgs" -Value "0" -Desc "Disabling start menu and search tracking"
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Key "SubscribedContent-353694Enabled" -Value "0" -Desc "Disabling suggested content"
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Key "SubscribedContent-353696Enabled" -Value "0"
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Key "SubscribedContent-338393Enabled" -Value "0"

    # Privacy & security > Speech
    SetReg -Path "Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Key "HasAccepted" -Value "0" -Desc "Disabling speech recognition"

    # Privacy & security > Inking & typing personalisation
    SetReg -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Key "AllowLinguisticDataCollection" -Value "0" -Desc "Disabling inking"

    # Privacy & security > Diagnostics & feedback
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\Privacy" -Key "TailoredExperiencesWithDiagnosticDataEnabled" -Value "0" -Desc "Disabling tailored experiences"
}

#========================================
# Privacy - End
#========================================
# Security - Start
#========================================

function DisableNetBiosSMB {
    # https://marklewis.blog/2017/07/05/netbios-and-smb1-kill-them-with-fire/
    Write-Host ""
    Write-Host "Disable NetBIOS and SMB." -BackgroundColor Black
    Write-Host ""

    Write-Host "Disabling NetBIOS for each network interface..." -NoNewline
    $adapters = (Get-WmiObject win32_networkadapterconfiguration)
    foreach ($adapter in $adapters) {
        $adapter.settcpipnetbios(2) | Out-Null
    }
    Write-Host " done." -ForegroundColor Green

    SetReg -Path "SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Key "NetbiosOptions" -Value "2" -Desc "Disabling NetBIOS over TCP/IP through registry"

    Write-Host "Disabling SMB Server..." -NoNewline
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
    Write-Host " done." -ForegroundColor Green
}

function MiscSecurity {
    Write-Host ""
    Write-Host "Miscellaneous registry changes for security purposes." -BackgroundColor Black
    Write-Host ""

    # Disable Link-Local Multicast Name Resolution (LLMNR) protocol.
    # https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
    SetReg -Path "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Key "EnableMulticast" -Value "0" -Desc "Disabling Link-Local Multicast Name Resolution"

    # Disable Wi-Fi Sense.
    SetReg -Path "SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Key "Value" -Value "0" -Desc "Disabling Wi-Fi hotspot reporting"
    SetReg -Path "SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Key "Value" -Value "0" -Desc "Disabling Wi-Fi hotspot auto connection"
    SetReg -Path "SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Key "AutoConnectAllowedOEM" -Value "0" -Desc "Disabling OEM allowed auto connect"

    # Disable remote assistance.
    SetReg -Path "SYSTEM\CurrentControlSet\Control\Remote Assistance" -Key "fAllowToGetHelp" -Value "0" -Desc "Disabling remote assistance"
    SetReg -Path "SYSTEM\CurrentControlSet001\Control\Remote Assistance" -Key "fAllowToGetHelp" -Value "0"
    SetReg -Path "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fAllowToGetHelp" -Value "0"
}

#========================================
# Security - End
#========================================
# Performance - Start
#========================================

function SetAllDevicesMSI {
    # https://forums.guru3d.com/threads/windows-line-based-vs-message-signaled-based-interrupts-msi-tool.378044/
    Write-Host ""
    Write-Host "Set all PCI devices that support message signaled interrupts to use MSI." -BackgroundColor Black
    Write-Host ""

    $devices = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -Recurse -ErrorAction SilentlyContinue -Depth 5 | Where-Object { $_.PSChildName -Like 'MessageSignaledInterruptProperties' }

    foreach ($device in $devices) {
        $path = $device -replace "HKEY_LOCAL_MACHINE","HKLM:"
        $deviceName = (Get-ItemProperty -Path (Split-Path (Split-Path (Split-Path $path)))).DeviceDesc.split(';')[1]
        SetReg -Path ($device -replace "HKEY_LOCAL_MACHINE","") -Key "MSISupported" -Value "1" -Desc ("Setting $deviceName")
    }
}

function SetUltimatePowerPlan {
    # https://www.howtogeek.com/368781/how-to-enable-ultimate-performance-power-plan-in-windows-10/
    Write-Host ""
    Write-Host "Set power plan to hidden Ultimate Performance power plan." -BackgroundColor Black
    Write-Host ""

    Write-Host "Unhiding 'Ultimate Performance' power plan..." -NoNewline
    $powerPlanInstance = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "ElementName='Ultimate Performance'"
    if ($null -eq $powerPlanInstance) {
        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
        $powerPlanInstance = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "ElementName='Ultimate Performance'"
    }
    Write-Host " done." -ForegroundColor Green

    Write-Host "Assigning power plan..." -NoNewline
    $powerPlanGUID = $powerPlanInstance.InstanceID.tostring().Substring(21,36)
    powercfg -setactive $powerPlanGUID
    Write-Host " done." -ForegroundColor Green
}

function UninstallBloatware {
    # Mostly guesswork, but no apps removed should impact experience with the main OS. Not an exhaustive list.
    Write-Host ""
    Write-Host "Uninstall bloatware installed by default." -BackgroundColor Black
    Write-Host ""

    Write-Host "Uninstalling Microsoft OneDrive..." -NoNewline
    $uninstallPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $oneDrive = Get-ChildItem -Path $uninstallPath | Get-ItemProperty | Where-Object {$_.DisplayName -Like "*OneDrive*" }
    if ($null -ne $oneDrive) {
        Invoke-Expression $oneDrive.UninstallString
        Write-Host " done." -ForegroundColor Green
    }
    else {
        Write-Host " not installed." -ForegroundColor Yellow
    }

    $apps = @(
        "Microsoft.BingWeather"
        "Microsoft.BingNews"
        "Microsoft.GamingApp"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MicrosoftStickyNotes"
        "Microsoft.People"
        "Microsoft.PowerAutomateDesktop"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Todos"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "MicrosoftWindows.Client.WebExperience"
        "Microsoft.WindowsStore"
        "Microsoft.YourPhone"
        "Microsoft.ZuneVideo"
        "Microsoft.ZuneMusic"
    )

    UninstallAppxPackages($apps)

    Write-Host "Remove advert tiles from start menu..." -NoNewline
    $initialPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount"
    $placeholder = Get-ChildItem -Path $initialPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -Like "*windows.data.placeholdertilecollection" }
    Remove-ItemProperty -Path (($placeholder.Name -replace "HKEY_CURRENT_USER","HKCU:") + "\Current") -Name "Data"
    Write-Host " done." -ForegroundColor Green
}

function RemoveXbox {
    # https://answers.microsoft.com/en-us/xbox/forum/all/xbox-game-bar-refuses-to-un-install/ccbb60ec-20df-41a3-9235-066a865d79ba
    Write-Host ""
    Write-Host "Remove Xbox Game Bar and overlay." -BackgroundColor Black
    Write-Host ""

    $apps = @(
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
    )

    UninstallAppxPackages($apps)

    $services = @(
        "XboxGipSvc"
        "XblAuthManager"
        "XblGameSave"
        "XboxNetApiSvc"
    )

    DisableServices($services)

    Write-Host "Disabling Xbox related scheduled tasks..." -NoNewline
    Disable-ScheduledTask -TaskPath "\Microsoft\XblGameSave\" -TaskName "XblGameSaveTask" | Out-Null
    Write-Host " done." -ForegroundColor Green

    SetReg -Path "Software\Microsoft\GameBar" -Key "UseNexusForGameBarEnabled" -Value "0" -Desc "Disabling gamebar in registry"
}

function MiscPerformance {
    Write-Host ""
    Write-Host "Miscellaneous changes for performance boosts." -BackgroundColor Black
    Write-Host ""

    # Disable NTFS last access update.
    # https://forums.guru3d.com/threads/ntfs-disable-last-access-update-file-time-stamp-windows-10-april-1803-update.421228/
    Write-Host "Disabling NTFS last access update..." -NoNewline
    fsutil behavior set disablelastaccess 1 | Out-Null
    Write-Host " done." -ForegroundColor Green

    # Disable superfetch.
    # https://www.tenforums.com/tutorials/99821-enable-disable-superfetch-windows.html
    DisableService -Name "SysMain" -Desc "Disabling Superfetch"
    
    # Increase svchost.exe splitting threshold to 64GB.
    # https://www.kapilarya.com/fix-high-disk-usage-by-service-host-svchost-exe-in-windows-10
    SetReg -Path "SYSTEM\CurrentControlSet\Control" -Key "SvcHostSplitThresholdInKB" -Value "67108864" -Desc "Increasing svchost.exe splitting threshold"

    # Disable timeout detection and recovery (TDR). We shouldn't be needing to debug hardware. 
    # https://docs.microsoft.com/en-gb/windows-hardware/drivers/display/tdr-registry-keys
    SetReg -Path "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Key "TdrDelay" -Value "0" -Desc "Disabling TDR"
    SetReg -Path "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Key "TdrLevel" -Value "0"
    SetReg -Path "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Key "TdrDdiDelay" -Value "0"
    SetReg -Path "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Key "TdrTestMode" -Value "0"
    SetReg -Path "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Key "TdrDebugMode" -Value "0"
    SetReg -Path "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Key "TdrLimitTime" -Value "0"
    SetReg -Path "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Key "TdrLimitCount" -Value "0"

    # Disable Windows Power Throttling mechanism.
    # https://www.tenforums.com/tutorials/99445-how-enable-disable-power-throttling-windows-10-a.html
    SetReg -Path "SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Key "PowerThrottlingOff" -Value "1" -Desc "Disabling power throttling"

    # Adjust process scheduling to [long quantum] + [variable foreground quantum] + [high foreground boost]
    # This should provide the smoothest FPS and least jitter at the small expense of input latency.
    # https://docs.google.com/document/d/1c2-lUJq74wuYK1WrA_bIvgb89dUN0sj8-hO3vqmrau4/edit#
    SetReg -Path "SYSTEM\CurrentControlSet\Control\PriorityControl" -Key "Win32PrioritySeparation" -Value "22" -Desc "Adjusting process scheduling"

    # Disable Malicious Software Removal Tool (MSRT).
    # https://winaero.com/disable-malicious-software-removal-tool/
    SetReg -Path "SOFTWARE\Policies\Microsoft\MRT" -Key "DontOfferThroughWUAU" -Value "1" -Desc "Disabling MSRT"

    # Disable hibernation and fast startup.
    # https://www.windowscentral.com/how-disable-windows-10-fast-startup
    SetReg -Path "SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Key "HiberbootEnabled" -Value "0" -Desc "Disabling fast startup"
    Write-Host "Disabling hibernation..." -NoNewline
    powercfg -hibernate OFF
    Write-Host " done." -ForegroundColor Green

    # Configure clock timers to prevent microstuttering.
    # https://www.reddit.com/r/buildapc/comments/c77wtu/you_should_know_that_if_youre_getting_high_fps_in/
    Write-Host "Disabling dynamic tick..." -NoNewline
    bcdedit -set disabledynamictick yes | Out-Null
    Write-Host " done." -ForegroundColor Green
    Write-Host "Setting platform tick to default..." -NoNewline
    bcdedit -deletevalue useplatformtick | Out-Null
    Write-Host " done." -ForegroundColor Green
    Write-Host "Enabling enhanced timestamp counter synchronization..." -NoNewline
    bcdedit -set tscsyncpolicy enhanced | Out-Null
    Write-Host " done." -ForegroundColor Green
}

function NetworkOptimisation {
    Write-Host ""
    Write-Host "Perform network optimisations." -BackgroundColor Black
    Write-Host ""

    # Decrease size threshold for UDP packets to be "fast sent". Theory is that larger packets will not be gaming related
    # and therefore not latency sensitive, so by decreasing the threshold only small packets will be fast sent. Default
    # value is 1000 (4096 bytes), modified value is 500 (1280 bytes). Value is experimental, little to no documentation
    # to be found online.
    # https://www.speedguide.net/articles/windows-2kxp-registry-tweaks-157
    SetReg -Path "SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Key "FastSendDatagramThreshold" -Value "500" -Desc "Decreasing threshold for UDP packets to be fast sent"
    SetReg -Path "SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Key "FastCopyReceiveThreshold" -Value "500"

    # TCP Optimizer
    Write-Host "Applying network settings from TCP Optimizer..." -NoNewline
    Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
    Set-NetTCPSetting -SettingName internet -EcnCapability Default
    Set-NetTCPSetting -SettingName internet -InitialRto 2000
    SetReg -Path "Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Key "SystemResponsiveness" -Value "10"
    SetReg -Path "Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Key "NetworkThrottlingIndex" -Value "4294967295"
    SetReg -Path "Software\Policies\Microsoft\Windows\Psched" -Key "NonBestEffortLimit" -Value "0"
    SetReg -Path "Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Key "iexplore.exe" -Value "10"
    SetReg -Path "Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Key "explorer.exe" -Value "10"
    SetReg -Path "Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Key "explorer.exe" -Value "10"
    SetReg -Path "Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Key "iexplore.exe" -Value "10"
    SetReg -Path "System\ControlSet001\Control\Session Manager\Memory Management" -Key "LargeSystemCache" -Value "1"
    SetReg -Path "System\ControlSet001\Services\LanmanServer\Parameters" -Key "Size" -Value "3"
    SetReg -Path "System\ControlSet001\Services\Tcpip\Parameters" -Key "MaxUserPort" -Value "65534"
    SetReg -Path "System\ControlSet001\Services\Tcpip\Parameters" -Key "TcpTimedWaitDelay" -Value "30"
    SetReg -Path "System\ControlSet001\Services\Tcpip\Parameters" -Key "DefaultTTL" -Value "64"
    SetReg -Path "System\ControlSet001\Services\Tcpip\QoS" -Key "Do not use NLA" -Value "1"
    SetReg -Path "System\ControlSet001\Services\Tcpip\ServiceProvider" -Key "HostsPriority" -Value "5"
    SetReg -Path "System\ControlSet001\Services\Tcpip\ServiceProvider" -Key "LocalPriority" -Value "4"
    SetReg -Path "System\ControlSet001\Services\Tcpip\ServiceProvider" -Key "NetbtPriority" -Value "7"
    SetReg -Path "System\ControlSet001\Services\Tcpip\ServiceProvider" -Key "DnsPriority" -Value "6"
    Write-Host " done." -ForegroundColor Green
}

#========================================
# Performance - End
#========================================
# QoL - Start
#========================================

function MiscQoL {
    Write-Host ""
    Write-Host "Perform quality of life adjustments." -BackgroundColor Black
    Write-Host ""

    # Disable Windows error reporting.
    SetReg -Path "SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Key "Disabled" -Value "1" -Desc "Disabling error reporting"
    
    # Disable sticky keys prompt and language keys.
    Write-Host "Disabling sticky keys and toggle keys..." -NoNewline
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122"
    Write-Host " done." -ForegroundColor Green
    
    # Disable automatic updates even if Windows update service is on.
    SetReg -Path "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "NoAutoUpdate" -Value "1" -Desc "Disable automatic updates"
    SetReg -Path "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "AUOptions" -Value "2"

    # No auto reboot with logged on users.
    SetReg -Path "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "NoAutoRebootWithLoggedOnUsers" -Value "1" -Desc "Disabling auto reboot"

    # Remove delay on startup and shutdown.
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Key "StartupDelayInMSec" -Value "0" -Desc "Removing delay on startup"
    SetReg -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shutdown\Serialize" -Key "StartupDelayInMSec" -Value "0" -Desc "Removing delay on shutdown"

    # Enable verbose startup/shutdown messages.
    SetReg -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Key "VerboseStatus" -Value "1" -Desc "Enabling verbose startup/shutdown messages"
    
    # Enable BSOD details instead of smiley.
    SetReg -Path "System\CurrentControlSet\Control\CrashControl" -Key "DisplayParameters" -Value "1" -Desc "Enabling BSOD details"
    
    # Apply mouse tweaks.
    Write-Host "Applying mouse tweaks..." -NoNewline
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type String -Value "10"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" -Name "CursorSensitivity" -Type String -Value "2710"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" -Name "CursorUpdateInterval" -Type String -Value "1"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" -Name "IRRemoteNavigationDelta" -Type String -Value "1"
    Write-Host " done." -ForegroundColor Green

    # Minor explorer tweaks.
    Write-Host "Applying explorer tweaks..." -NoNewline
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "IconSpacing" -Type String -Value "-1125"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "IconVerticalSpacing" -Type String -Value "-1125"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type String -Value "64"
    Write-Host " done." -ForegroundColor Green
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Key "HideFileExt" -Value "0" -Desc "Unhiding file extensions"
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Key "ShowSuperHidden" -Value "1" -Desc "Unhiding OS files"

    # Enable dark mode.
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Key "AppsUseLightTheme" -Value "0" -Desc "Enabling dark mode"
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Key "SystemUsesLightTheme" -Value "0"

    # Disable auto play and auto run.
    SetReg -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Key "DisableAutoplay" -Value "1" -Desc "Disabling auto play"
    SetReg -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Key "NoDriveTypeAutoRun" -Value "255" -Desc "Disabling auto run"

    # Disable UAC.
    SetReg -Path "Software\Microsoft\Windows\CurrentVersion\policies\system" -Key "EnableLUA" -Value "0" -Desc "Disabling UAC"
}

#========================================
# QoL - End
#========================================

# Privacy
DisableTelemetry
UninstallCortana
MiscPrivacy

# Security
DisableNetBiosSMB
MiscSecurity

# Performance
SetAllDevicesMSI
SetUltimatePowerPlan
UninstallBloatware
RemoveXbox
MiscPerformance
NetworkOptimisation

# QoL
MiscQoL

Write-Host ""
Write-Host "Script complete!" -BackgroundColor Green -ForegroundColor Black
Write-Host ""

PAUSE
