# Windows All-In-One Script
Removes bloatware, tidies interfaces, and updates/installs my preferred default programs with Chocolatey.

### Run
1. Modify the following configuration files as needed
    - [`chocoInstall.txt`](./chocoInstall.txt)
    - [`Default.preset`](./Default.preset)
    - [`hosts.txt`](./hosts.txt)
    - [`telemetryIPs.txt`](./telemetryIPs.txt)

2. Run [`Default.cmd`](./Default.cmd) as administrator.

### References
- Originally forked from https://github.com/Disassembler0/Win10-Initial-Setup-Script
- https://github.com/chocolatey/choco
- https://github.com/lord-carlos/nvidia-update
- https://github.com/CHEF-KOCH/GamingTweaks
- https://github.com/W4RH4WK/Debloat-Windows-10
- https://gist.github.com/IntergalacticApps/675339c2b805b4c9c6e9a442e0121b1d
- https://github.com/Nummer/Destroy-Windows-10-Spying

### Hosts
This script will append to the system hosts file, blocking all requests by redirecting these host names to `127.0.0.1`. You can change the hosts it will append in [`hosts.txt`](./hosts.txt).

### Chocolatey
This script uses Chocolatey to automate updating and installing windows packages. You can change the packages it checks in [`chocoInstall.txt`](./chocoInstall.txt).

Some packages have optional install parameters, you can automate installation by seperating the desired parameter in `chocoInstall.txt` with a `|`.
For example, to install [git](https://chocolatey.org/packages/git.install) with its no GUI parameter,
> `choco install git.install --params "/NoGuiHereIntegration"`

The line in `chocoInstall.txt` would look like so,
> `git.install|--params "/NoGuiHereIntegration"`

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
