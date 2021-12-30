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

# Add telemetry ips to firewall
Function DisableTeleIps{
	Write-Output "Adding telemetry ips to firewall"
    $ips = [string[]](Get-Content $psscriptroot\telemetryIPs.txt | Select-Object -Skip 3)
	Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
	New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
	-Action Block -RemoteAddress ($ips)
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

Function DisableNewsAndInterests {
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
}

# https://www.askvg.com/security-alert-immediately-disable-printer-spooler-service-in-windows/
Function DisablePrintSpooler {
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Type DWord -Value 2
	HKEY_LOCAL_MACHINE
}

# Hide Widgets Button
Function HideTaskBarWidgets {
	Write-Output "Hiding Widgets Task Bar button..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0
}

# Hide Chat Button
Function HideTaskBarChat {
	Write-Output "Hiding MS Teams Task Bar button..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0
}

# Align task bar left
Function TaskBarAlignLeft {
	Write-Output "Task bar left align..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 0
}

# set similar colors to windows 10: black start menu, blue accent, white windows
Function colors {
	Write-Output "Show Accent Color on Title Bars and Windows Borders..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 1
	Write-Output "Windows mode to dark..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
	Write-Output "App mode to light..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1
}

# old right click menu
Function oldRightClickMenu {
	reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
}