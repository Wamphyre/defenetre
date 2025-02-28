@echo off
setlocal EnableDelayedExpansion
color 0A
title Windows 10/11 Optimizer

:: Run as administrator
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

echo.
echo ===========================================
echo  WINDOWS 10/11 OPTIMIZER
echo ===========================================
echo.
echo This script will perform the following actions:
echo  - Disable telemetry and tracking services
echo  - Remove preinstalled applications (bloatware)
echo  - Optimize system performance
echo  - Disable system restore
echo  - Disable automatic defragmentation
echo  - Disable disk indexing
echo  - Disable page file
echo  - Disable fast boot
echo  - Disable security mitigations
echo  - Disable Power Throttling
echo  - Remove startup delays
echo  - Speed up shutdown time
echo  - Disable Windows Defender
echo  - Improve RAM management and system speed
echo  - Adjust settings to maximize speed
echo.
pause
cls

echo ===========================================
echo  DISABLING TELEMETRY
echo ===========================================
echo.

:: Disable telemetry services
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop dmwappushservice
sc config dmwappushservice start= disabled
sc stop WMPNetworkSvc
sc config WMPNetworkSvc start= disabled

:: Disable telemetry-related scheduled tasks
schtasks /change /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /change /tn "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable

:: Disable data collection
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

:: Disable Windows suggestions
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f

:: Disable ads and tracking
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

:: Disable Windows diagnostics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f

echo Telemetry disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  REMOVING BLOATWARE
echo ===========================================
echo.

:: Remove preinstalled applications (Bloatware)
powershell -Command "Get-AppxPackage 'Microsoft.3DBuilder' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.BingFinance' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.BingNews' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.BingSports' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.BingWeather' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.GetStarted' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.MicrosoftOfficeHub' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.MicrosoftSolitaireCollection' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.Office.OneNote' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.People' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.SkypeApp' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.Windows.Photos' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.WindowsAlarms' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.WindowsCamera' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'microsoft.windowscommunicationsapps' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.WindowsMaps' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.WindowsPhone' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.WindowsSoundRecorder' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.XboxApp' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.ZuneMusic' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.ZuneVideo' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.XboxGamingOverlay' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.Xbox.TCUI' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.YourPhone' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.Gethelp' | Remove-AppxPackage"
powershell -Command "Get-AppxPackage 'Microsoft.Messaging' | Remove-AppxPackage"

echo Bloatware removed.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  OPTIMIZING PERFORMANCE
echo ===========================================
echo.

:: Optimize search service
sc config WSearch start= delayed-auto

:: Configure visual performance settings
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9032078010000000 /f

:: Disable transparency
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f

:: Unlock and activate maximum performance power plan
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -change -monitor-timeout-ac 10
powercfg -change -monitor-timeout-dc 5
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 15

:: Optimize prefetch and superfetch
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 3 /f

:: SSD Optimization (if applicable)
fsutil behavior set DisableDeleteNotify 0

:: Disable hibernation to free up space
powercfg -h off

echo Performance optimized.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING PAGE FILE
echo ===========================================
echo.

:: Completely disable page file
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset delete

:: Confirm it's disabled through registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v PagingFiles /t REG_MULTI_SZ /d "" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

echo Page file disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING FAST BOOT
echo ===========================================
echo.

:: Disable Fast Boot
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f

:: Disable in power settings
powercfg -setacvalueindex scheme_current sub_buttons pbuttonaction 0
powercfg -setdcvalueindex scheme_current sub_buttons pbuttonaction 0
powercfg -setactive scheme_current

echo Fast Boot disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING SYSTEM RESTORE
echo ===========================================
echo.

:: Completely disable System Restore
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f

:: Stop and disable System Restore service
sc stop srservice
sc config srservice start= disabled

:: Remove existing restore points
vssadmin delete shadows /all /quiet

echo System Restore disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING AUTOMATIC DEFRAGMENTATION
echo ===========================================
echo.

:: Disable scheduled defragmentation tasks
schtasks /change /tn "Microsoft\Windows\Defrag\ScheduledDefrag" /disable

:: Disable automatic defragmentation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout" /v EnableAutoLayout /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Defrag" /v EnableAutoDefrag /t REG_DWORD /d 0 /f

echo Automatic defragmentation disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING DISK INDEXING
echo ===========================================
echo.

:: Stop and disable Windows Search indexing service
sc stop WSearch
sc config WSearch start= disabled

:: Disable indexing
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v PreventIndexOnBattery /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v PreventIndexingLowDiskSpaceMB /t REG_DWORD /d 0x001e8480 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableRemovableDriveIndexing /t REG_DWORD /d 1 /f

:: Disable file indexing on drive C:
powershell -Command "$indexObj = (New-Object -ComObject Search.FilterHandler); $catalogManager = $indexObj.GetCatalog('SystemIndex'); $catalogManager.SetHiddenColumns(@('C:'))"

echo Disk indexing disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING SECURITY MITIGATIONS
echo ===========================================
echo.

:: Disable security mitigations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v DisableTsx /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /f

echo Security mitigations disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING POWER THROTTLING
echo ===========================================
echo.

:: Disable Power Throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f

echo Power Throttling disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  REMOVING STARTUP DELAYS
echo ===========================================
echo.

:: Remove startup delay
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f

echo Startup delays removed.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  SPEEDING UP SHUTDOWN TIME
echo ===========================================
echo.

:: Speed up shutdown time
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 300 /f

echo Shutdown time accelerated.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  FIXING MEMORY LEAK IN WINDOWS 10
echo ===========================================
echo.

:: Fix memory leak in Windows 10
reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v Start /t REG_DWORD /d 4 /f

echo Memory leak fixed.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING WINDOWS DEFENDER
echo ===========================================
echo.

:: Disable Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

echo Windows Defender disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  DISABLING LARGESYSTEMCACHE
echo ===========================================
echo.

:: Disable LargeSystemCache
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 0 /f

echo LargeSystemCache disabled.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  IMPROVING RAM MANAGEMENT AND SPEED
echo ===========================================
echo.

:: Improve RAM management and system speed
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 100 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 300 /f
reg add "HKCU\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_SZ /d 1000 /f

echo RAM management and speed improved.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  IMPROVING SYSTEM RESPONSE AND NETWORK
echo ===========================================
echo.

:: Improve system response and network speed
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xffffffff /f

echo System response and network speed improved.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  ADJUSTING ADDITIONAL SETTINGS
echo ===========================================
echo.

:: Disable Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f

:: Disable activity history
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f

:: Disable unnecessary services
sc config SysMain start= disabled
sc stop SysMain
sc config MapsBroker start= disabled
sc stop MapsBroker
sc config DoSvc start= disabled
sc stop DoSvc

echo Additional settings adjusted.
echo.
timeout /t 3 >nul
cls

echo ===========================================
echo  COMPLETED
echo ===========================================
echo.
echo Windows optimization has finished.
echo.
echo NOTE: Some of these optimizations may affect system security
echo and are not recommended for all users. Use at your own risk.
echo.
echo It is recommended to restart the system to apply all changes.
echo.
choice /c YN /m "Do you want to restart now? (Y/N)"
if %errorlevel% equ 1 shutdown /r /t 10 /c "Restarting to apply optimizations"
if %errorlevel% equ 2 echo.&echo Remember to restart manually to apply all changes.&echo.

pause
exit