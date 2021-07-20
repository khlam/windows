#Disable various services
Function DisableServices {
	$services = @(
	    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
	    "DiagTrack"                                # Diagnostics Tracking Service
	    #"dmwappushservice"                        # WAP Push Message Routing Service (see known issues)
	    "HomeGroupListener"                        # HomeGroup Listener
	    "HomeGroupProvider"                        # HomeGroup Provider
	    "lfsvc"                                    # Geolocation Service
	    "MapsBroker"                               # Downloaded Maps Manager
	    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
	    "RemoteAccess"                             # Routing and Remote Access
	    "RemoteRegistry"                           # Remote Registry
	    "SharedAccess"                             # Internet Connection Sharing (ICS)
	    "TrkWks"                                   # Distributed Link Tracking Client
	    "WbioSrvc"                                 # Windows Biometric Service
	    #"WlanSvc"                                 # WLAN AutoConfig
		"WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
		"XboxGipSvc"
		"xbgm"
	    #"XblAuthManager"                          # Xbox Live Auth Manager
	    #"XblGameSave"                             # Xbox Live Game Save Service
		#"XboxNetApiSvc"                           # Xbox Live Networking Service
		"WinHttpAutoProxySvc"					   # Web Proxy Auto Discovery
		"ndu"                                      # Windows Network Data Usage Monitor
		"Spooler"								   # Print spooler
	)

	foreach ($service in $services) {
	    Write-Output "Trying to disable $service"
	    Get-Service -Name $service | Set-Service -StartupType Disabled
	}
}

#Check if reg value exists
# Source: https://gallery.technet.microsoft.com/scriptcenter/deactivate-Nagle-Algorithm-66ca7608
Function Exists-RegistryValue($pspath, $propertyname) {
    $exists = Get-ItemProperty -Path "$pspath" -Name "$propertyname" -ea SilentlyContinue
    If (($exists -ne $null) -and ($exists.Length -ne 0)) {
        Return $true
    }
    Return $false
}

# Nvidia Driver Check, cleans and installs new drivers
# Source: https://github.com/lord-carlos/nvidia-update
Function UpdateNvidiaDrivers{
	# Checking currently installed driver version
	Write-Host "Updating Nvidia drivers..."
	try {  
		$ins_version = (Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.devicename -like "*nvidia*" -and $_.devicename -notlike "*audio*"}).DriverVersion.SubString(7).Remove(1,1).Insert(3,".")
	} catch {
		Write-Host "Unable to detect a compatible Nvidia device."
		return;
	}
	Write-Host "Installed version: `t$ins_version"

	# Set locations
	$location = "US"
	$extractDir = [Environment]::GetFolderPath("Desktop")

	# Checking if 7zip is installed
	if (Test-Path $env:programfiles\7-zip\7z.exe) {
		$archiverProgram = "$env:programfiles\7-zip\7z.exe"
	} else {
		Write-Host "7zip not installed. Cannot extract driver package. Cancelling."
		return;
	}

	# Checking latest driver version from Nvidia website
	$link = Invoke-WebRequest -Uri 'https://www.nvidia.com/Download/processFind.aspx?psid=101&pfid=816&osid=57&lid=1&whql=1&lang=en-us&ctk=0' -Method GET -UseBasicParsing
	$link -match '<td class="gridItem">([^<]+?)</td>' | Out-Null
	$version = $matches[1]
	Write-Host "Latest version `t`t$version"

	# Comparing installed driver version to latest driver version from Nvidia
	if($version -eq $ins_version) {
		Write-Host "Latest Nvidia Drivers installed."
		return;
	}

	# Confirm install
	Write-Host -nonewline "New Nvidia Driver $version found. Continue with install? (Y/N) "
	$response = read-host
	if ( $response -ne "Y" ) { return; }

	# Checking Windows version
	if ([Environment]::OSVersion.Version -ge (new-object 'Version' 9,1)) {
		$windowsVersion = "win10"
	} else {
		$windowsVersion = "win8-win7"
	}

	# Checking Windows version
	if ((Get-WmiObject win32_operatingsystem | Select-Object osarchitecture).osarchitecture -eq "64-bit")
	{
		$windowsArchitecture = "64bit"
	} else {
		$windowsArchitecture = "32bit"
	}

	# Generating the download link
	$url = "http://$location.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-whql.exe"
	Write-Host $url

	# Create a new temp folder NVIDIA
	$nvidiaTempFolder = "$extractDir\nvidia_$version"
	New-Item -Path $nvidiaTempFolder -ItemType Directory 2>&1 | Out-Null

	# Download installer
	$dlFile = "$nvidiaTempFolder\$version.exe"
	Write-Host "Downloading $version to $dlFile"
	Start-BitsTransfer -Source $url -Destination $dlFile

	# Extracting setup files
	$extractFolder = "$nvidiaTempFolder\$version"
	$filesToExtract = "Display.Driver NVI2 EULA.txt ListDevices.txt setup.cfg setup.exe"
	Write-Host "Download finished, extracting files..."
	if ($archiverProgram -eq "$env:programfiles\7-zip\7z.exe") {
		Start-Process -FilePath $archiverProgram -ArgumentList "x $dlFile $filesToExtract -o""$extractFolder""" -wait
	}
	# Remove unneeded dependencies from setup.cfg
	(Get-Content "$extractFolder\setup.cfg") | Where-Object {$_ -notmatch 'name="\${{(EulaHtmlFile|FunctionalConsentFile|PrivacyPolicyFile)}}'} | Set-Content "$extractFolder\setup.cfg" -Encoding UTF8 -Force

	# Installing drivers
	Write-Host "Installing $version..."
	$install_args = "-s -noreboot -noeula -clean"
	Start-Process -FilePath "$extractFolder\setup.exe" -ArgumentList $install_args -wait
}

# Add telemetry ips to firewall
Function DisableTeleIps{
	Write-Output "Adding telemetry ips to firewall"
    $ips = [string[]](Get-Content $psscriptroot\telemetryIPs.txt | Select-Object -Skip 3)
	Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
	New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
	-Action Block -RemoteAddress ($ips)
}

# Change volume control to classic style
Function ChangeVolumeClassic {
	Write-Output "Changing volume control to classic style..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Type Dword -Value 0
}


## Install Chocolatey if not already installed
Function InstallChoco {
	Write-Host "Installing chocolatey..."
	$error.clear()
	try { choco feature enable --name=useRememberedArgumentsForUpgrades }
	catch { 
		Write-Host -nonewline "Install chocolatey? (Y/N) "
		$response = read-host
		if ( $response -ne "Y" ) { return; }
		Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	}
	if (!$error) {
		Write-Host "Chocolatey already installed."
	}
}

## Install all packages in chocoInstall.txt
Function InstallChocoPkgs {
	$file = "$psscriptroot\chocoInstall.txt"
	Write-Host "Installing all packages in $file that are not already installed..."
	if (Test-Path $file) {
        $toInstall = @()
        $params = @()
        foreach($line in Get-Content $file){
            $line = $line.split('|')
            $toInstall += $line[0]
            if (!($line[1] -eq "")) {
                $params += $line[1]
            }else {
                $params += ""
            }
        }
		if (!($toInstall.count -eq 0)) {
            $installed = [string[]](choco list --local-only | ForEach {"$_".Split(" ")[0]})
			$notInstalled = $toInstall | Where {$installed -NotContains $_}
			
			if (!($notInstalled.count -eq 0)){
				Write-Host "Found packages in $file that are not installed: $notInstalled"
				Write-Host -NoNewline "Install? (Y/N)"
				$response = read-host
				if ( $response -ne "Y" ) { return; }
				ForEach ($j in $notInstalled) {
                    $i = $toInstall.IndexOf($j)
                    $p = $params[$i]
                    Write-Host choco install $j $p -y 
					Invoke-Expression "choco install $j $p -y"
				}
			}else {
				Write-Host "All packages from $file installed."
			}
		}
	}else {
		Write-Host "Cannot find chocoInstall.txt."
	}
}

# Update choco
Function UpdateChoco {
	Write-Host "Updating chocolatey..."
	$error.clear()
	try { choco feature enable --name=useRememberedArgumentsForUpgrades }
	catch { Write-Host "Chocolatey is not installed." }
	if (!$error) {
		choco feature enable --name=useRememberedArgumentsForUpgrades
		choco upgrade chocolatey -y
		choco upgrade all -y
	}
}

Function DisableTransparency {
    Write-Host "Disabling Transparency"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type Dword -Value 0
}

## Set Gaming Performance to high priority
Function GamingRegSet{
	if ((Test-Path ${env:ProgramFiles(x86)}\Steam\)) # Assumption: If steam is not installed then there's no point adjusting PC performance for gaming
	{
		Write-Output "Set gaming performance to high priority..."
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type String -Value "False"
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xFFFFFFFF
	}
	else {
		Write-Host "Steam is not installed. Assuming gaming performance registry tweaks are not needed."
	}
}

## Disable wpad service
Function Disablewpad{
	Write-Output "Disabling wpad DNS queries..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDevolution" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Type DWord -Value 4
}

Function SetDefaultViewDetailed{
	Write-Output "Setting Explorer default view to Detailed..."
	Remove-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagsMRU" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\Sizer" -Recurse -ErrorAction SilentlyContinue

	If (!(Test-Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell")) {
		New-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" -Force | Out-Null
		Set-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" -Name "FolderType" -Type String -Value "NotSpecified"
		Set-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" -Name "SniffedFolderType" -Type String -Value "Generic"
		Set-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" -Name "KnownFolderDerivedFolderType" -Type String -Value "{57807898-8C4F-4462-BB63-71042380B109}"
	}

	If (!(Test-Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}")) {
		New-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}" -Force | Out-Null
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}" -Name "LogicalViewMode" -Type DWord -Value 1
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}" -Name "Mode" -Type DWord -Value 4
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}" -Name "GroupView" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}" -Name "GroupByDirection" -Type DWord -Value 1
	}
}

Function RemoveTextCopyPasteFormatOnStartup{
	$cwd = ($pwd).path
	$currentUser=[Environment]::UserName 
	$startupPath="C:/Users/$currentUser/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
	Write-Output "Copying clipboard-clear-text-format.exe to $startupPath..."
	Copy-Item "$psscriptroot\clipboard-clear-text-format.exe" -Destination $startupPath -Recurse -force
}

Function RemovePinToStartContext{
	Write-Output "Removing Pin To Start from context menu..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -LiteralPath "HKCR:\exefile\shellex\ContextMenuHandlers\PintoStartScreen" -ErrorAction SilentlyContinue
	Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\PintoStartScreen" -ErrorAction SilentlyContinue
}

# https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-executable-content-from-email-client-and-webmail
Function DefenderAttackSurfaceReduction {
	$services = @(
	    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" # Block executable content from email client and webmail
		"D4F940AB-401B-4EFC-AADC-AD5F3C50688A" # Block all Office applications from creating child processes
		"3B576869-A4EC-4529-8536-B80A7769E899" # Block Office applications from creating executable content
		"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" # Block Office applications from injecting code into other processes
		#"D3E037E1-3EB8-44C8-A917-57927947596D" # Block JavaScript or VBScript from launching downloaded executable content
		#"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" # Block execution of potentially obfuscated scripts
		"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" # Block Win32 API calls from Office macros
		#"01443614-cd74-433a-b99e-2ecdc07bfc25" # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
		#"c1db55ab-c21a-4637-bb3f-a12568109d35" # Use advanced protection against ransomware
		"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
		"d1e49aac-8f56-4280-b9ba-993a6d77406c" # Block process creations originating from PSExec and WMI commands
		"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" # Block untrusted and unsigned processes that run from USB
		"26190899-1602-49e8-8b27-eb1d0a1ce869" # Block Office communication application from creating child processes
		"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" # Block Adobe Reader from creating child processes
		"e6db77e5-3df2-4cf1-b95a-636979351e5b" # Block persistence through WMI event subscription
	)
	Write-Output "Enabling Windows Defender Attack Surface Reduction"
	foreach ($GUID in $services) {
	    Write-Output "Disabling $GUID"
		Add-MpPreference -AttackSurfaceReductionRules_Ids $GUID -AttackSurfaceReductionRules_Actions Enabled
	}
}

Function RemoveMeetNow {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1
}

Function RemoveCustomizeThisFolder {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoCustomizeThisFolder" -Value 1
}

Function RemoveNewsAndInterests {
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
}