# Win10-Config
This script removes bloatware, tidies up interface, and increases Windows 10 performance. My modifications include combining similar projects and my preferred Windows 10 settings. Important features include auto-updating NVIDIA GPU drivers, removing Nagle's algorithm, and purging more telemetry services.

### References
- https://github.com/Disassembler0/Win10-Initial-Setup-Script
- https://github.com/chocolatey/choco
- https://github.com/lord-carlos/nvidia-update
- https://github.com/CHEF-KOCH/GamingTweaks
- https://github.com/W4RH4WK/Debloat-Windows-10
- https://gist.github.com/IntergalacticApps/675339c2b805b4c9c6e9a442e0121b1d
- https://github.com/Nummer/Destroy-Windows-10-Spying

### Chocolatey
This script installs the following tools
- Default Installs
    - vlc
    - firefox
    - keepassxc
    - git
    - megasync
    - sumatrapdf
    - winscp
    - putty
    - visualstudiocode
    - hwmonitor
    - 7-zip

- Misc Installs
    - discord
    - cpu-z
    - deluge
    - steam
    - autohotkey

### Search Fix
Fix if script breaks windows search. This is due to some initialization not started by some MS services that are disabled for privacy.
1. Log into another admin account
2. Go to
    - `C:\Users\<ProblemUserName>\AppData\Local\Packages`
3. Delete folder named 
    - `Microsoft.Windows.Cortana....`
4. Log out and log back into main account
5. Start admin powershell and run command:
    - `Add-AppxPackage -DisableDevelopmentMode -Register "$(Get-AppxPackage -Name *Cortana* | Select -Expand InstallLocation)\AppXManifest.xml"`
    - This will re-register and enable Cortana.
6. Reboot
7. (Optional) Run win10 clean script again to disable Cortana. Start menu search should work.