# Win10-Config
This script removes bloatware, tidies interfaces, and increases Windows 10 performance. My modifications include combining similar projects and my preferred Windows 10 settings. Important features include automation with Chocolatey, auto-updating NVIDIA GPU drivers, removing Nagle's algorithm, and purging more telemetry services.

### References
This all-in-one script would not be possible without the knowledge shared by these talented individuals and teams.
- https://github.com/Disassembler0/Win10-Initial-Setup-Script
- https://github.com/chocolatey/choco
- https://github.com/lord-carlos/nvidia-update
- https://github.com/CHEF-KOCH/GamingTweaks
- https://github.com/W4RH4WK/Debloat-Windows-10
- https://gist.github.com/IntergalacticApps/675339c2b805b4c9c6e9a442e0121b1d
- https://github.com/Nummer/Destroy-Windows-10-Spying

### Chocolatey
This script uses Chocolatey to automate updating and installing windows packages. You can change the packages it installs in `chocoInstall.txt`. The following packages are default.
- vlc
- firefox
- keepassxc
- git.install
- megasync
- sumatrapdf.install
- winscp
- putty.install
- visualstudiocode
- hwmonitor
- 7zip.install
- discord
- cpu-z
- deluge
- steam
- autohotkey.install

### Search Fix [Depreciated]
The following steps fixed Windows search. This is due to some initialization not started by some MS services that are disabled for privacy. You should not need to do this more than once. I haven't had to do this for a while, it may no longer be necessary.
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