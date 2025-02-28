# Defenetre Windows Optimizer

## ⚠️ WARNING ⚠️

This script makes significant modifications to your Windows system that could potentially:
- Reduce system security
- Disable important Windows functionality
- Affect system stability
- Make your system more vulnerable to malware

**USE AT YOUR OWN RISK. The author(s) are not responsible for any data loss, system damage, or security issues that may arise from using this script.**

## Overview

Defenetre is a Windows batch script that aims to optimize Windows 10/11 performance by disabling various background services, telemetry features, and built-in applications. The name comes from the French word "défenestrer" which means "to throw out a window" - metaphorically removing unwanted Windows features.

## Features

The script performs the following optimizations:

### Privacy Enhancements
- Disables telemetry and data collection
- Disables diagnostic tracking services
- Turns off Windows suggestions and advertising
- Removes feedback mechanisms

### Performance Optimizations
- Removes pre-installed applications (bloatware)
- Optimizes visual performance settings
- Activates maximum performance power plan
- Disables page file (virtual memory)
- Disables hibernation
- Disables fast boot
- Disables system restore
- Disables automatic disk defragmentation
- Disables disk indexing
- Resolves memory leak issues

### Security Modifications
- Disables security mitigations (may increase vulnerability)
- Disables Windows Defender (not recommended)

### System Responsiveness
- Eliminates startup delays
- Reduces shutdown timeout
- Improves RAM management
- Enhances system responsiveness
- Optimizes network settings

## Usage

1. Download `defenetre.bat`
2. Right-click and select "Run as administrator" (or the script will automatically request elevation)
3. Review the list of actions that will be performed
4. Press any key to continue
5. The script will execute all optimizations
6. Choose whether to restart your system when complete (recommended)

## Requirements

- Windows 10 or Windows 11
- Administrator privileges

## Detailed Modifications

### Telemetry Disabling
- Stops and disables DiagTrack, dmwappushservice, and WMPNetworkSvc services
- Disables scheduled tasks related to telemetry
- Sets registry keys to prevent data collection
- Disables suggestions and advertisements

### Bloatware Removal
Uninstalls the following pre-installed applications:
- Microsoft 3D Builder
- Bing Finance, News, Sports, Weather
- Get Started
- Microsoft Office Hub
- Microsoft Solitaire Collection
- OneNote
- People
- Skype
- Photos
- Windows Alarms, Camera, Communications, Maps, Phone, Sound Recorder
- Xbox apps
- Zune Music and Video
- Your Phone
- Get Help
- Messaging

### Performance Optimizations
- Configures visual effects for performance
- Disables transparency
- Activates Ultimate Performance power plan
- Sets monitor timeouts and disables standby
- Optimizes prefetch and superfetch
- Configures SSD settings
- Disables hibernation
- Disables paging file (virtual memory)
- Disables fast boot
- Disables system restore
- Disables automatic defragmentation
- Disables disk indexing
- Disables security mitigations
- Disables Power Throttling
- Eliminates startup delays
- Accelerates shutdown time
- Fixes Windows 10 memory leaks
- Disables Windows Defender
- Optimizes LargeSystemCache
- Improves RAM and system speed settings
- Enhances system and network responsiveness
- Disables Cortana and activity history
- Disables unnecessary services (SysMain, MapsBroker, DeliveryOptimization)

## Disclaimer

This script makes significant changes to your Windows system. While it aims to improve performance, it may cause stability issues, security vulnerabilities, or unexpected behavior. It is provided "as is" without warranty of any kind. Use at your own risk.

## License

This script is released under the MIT License.