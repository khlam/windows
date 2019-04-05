# Win10-Config
This script removes bloatware, tidies interfaces, and increases Windows 10 performance. My modifications include combining similar projects and my preferred Windows 10 settings. Important features include automation with Chocolatey, auto-updating NVIDIA GPU drivers, removing Nagle's algorithm, and purging more telemetry services.

### Run
1. Modify the following configuration files as needed
    - [`chocoInstall.txt`](./chocoInstall.txt)
    - [`Default.preset`](./Default.preset)
    - [`hosts.txt`](./hosts.txt)
    - [`telemetryIPs.txt`](./telemetryIPs.txt)

2. Run [`Default.cmd`](./Default.cmd) as administrator.

### References
This all-in-one script would not be possible without the knowledge shared by these talented individuals and teams.
- https://github.com/Disassembler0/Win10-Initial-Setup-Script
- https://github.com/chocolatey/choco
- https://github.com/lord-carlos/nvidia-update
- https://github.com/CHEF-KOCH/GamingTweaks
- https://github.com/W4RH4WK/Debloat-Windows-10
- https://gist.github.com/IntergalacticApps/675339c2b805b4c9c6e9a442e0121b1d
- https://github.com/Nummer/Destroy-Windows-10-Spying

### Hosts
This script will append to the system hosts file, blocking all requests by redirecting these host names to `127.0.0.1`. You can change the hosts it will append in [`hosts.txt`](./hosts.txt).
The following host names are default.
- config.edge.skype.com
- nexusrules.officeapps.live.com
- www.google-analytics.com
- settings-win.data.microsoft.com
- vortex.data.microsoft.com
- wpad.lan
- self.events.data.microsoft.com

### Chocolatey
This script uses Chocolatey to automate updating and installing windows packages. You can change the packages it installs in [`chocoInstall.txt`](./chocoInstall.txt). The following packages are default.
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
The following steps fixed Windows search. This is due to some initialization not started by some MS services that are disabled for privacy. You should not need to do this more than once. This seems to have been fixed in some Windows update.
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