# Windows Build Script with Progress Output

# Check system requirements
Write-Host "[+] Checking system requirements (RAM >= 8GB, Free disk space >= 200GB)..." -ForegroundColor Cyan

# RAM check
$minRAMGB = 8
$ram = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB

# Disk space check on system drive
$minFreeGB = 200
$sysDrive = Get-PSDrive -Name (Get-Location).Path.Substring(0,1)
$freeSpace = $sysDrive.Free / 1GB

if ($ram -lt $minRAMGB -or $freeSpace -lt $minFreeGB) {
    Write-Host "[!] System does not meet the minimum requirements:" -ForegroundColor Red
    if ($ram -lt $minRAMGB) {
        Write-Host "    - RAM: $([math]::Round($ram,2)) GB detected, 8 GB required" -ForegroundColor Red
    }
    if ($freeSpace -lt $minFreeGB) {
        Write-Host "    - Free disk space: $([math]::Round($freeSpace,2)) GB available, 200 GB required" -ForegroundColor Red
    }
    Write-Host "[!] It is strongly recommended you stop now. This system does not meet the minimum requirements and the build is likely to fail." -ForegroundColor Red
    $continue = Read-Host "Do you want to continue anyway? (Y/N)"
    if ($continue -notmatch '^[Yy]$') {
        Write-Host "[X] Exiting script due to insufficient system resources." -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "[!] Proceeding against recommendation." -ForegroundColor Yellow
    }
}
Write-Host "[OK] System requirements met." -ForegroundColor Green

# Check internet connectivity
Write-Host "`n[+] Checking internet connectivity..." -ForegroundColor Cyan
$internetAccess = Test-Connection 8.8.8.8 -Count 1 -Quiet

if (-not $internetAccess) {
    Write-Warning "[!] No internet connection detected!"
    $confirmation = Read-Host "Continue anyway? (Y/N)"
    if ($confirmation -notmatch '^[Yy]$') {
        Write-Host "[X] Operation cancelled." -ForegroundColor Yellow
        exit
    }
}
Write-Host "[OK] Internet connectivity check complete." -ForegroundColor Green

# Check winget installation
Write-Host "`n[+] Checking for Winget installation..." -ForegroundColor Cyan
try {
    $wingetCheck = Get-Command winget -ErrorAction Stop
    Write-Host "[OK] Winget found at: $($wingetCheck.Source)" -ForegroundColor Green
} catch {
    Write-Warning "[!] Winget is not installed on this system!"
    $confirmation = Read-Host "Continue without winget? (Y/N)"
    if ($confirmation -notmatch '^[Yy]$') {
        Write-Host "[X] Exiting script." -ForegroundColor Yellow
        exit 1
    }
    Write-Warning "[!] Proceeding without winget - software management features will be disabled."
}

Write-Host "`n[+] Proceeding with main operations..." -ForegroundColor Cyan

# Check for pending updates
Write-Host "`n[+] Checking for pending Windows updates..." -ForegroundColor Cyan
if ((New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates.Count -gt 0) {
    Write-Warning "[!] System has pending updates! Run Get-WindowsUpdate to view them."
} else {
    Write-Host "[OK] System is up to date." -ForegroundColor Green
}

# Disable firewall and set system options
Write-Host "`n[+] Disabling firewalls and configuring system settings..." -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Write-Host "[OK] Firewall and power settings updated." -ForegroundColor Green

# Install AD modules
Write-Host "`n[+] Installing Active Directory modules..." -ForegroundColor Cyan
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
Write-Host "[OK] AD modules installed." -ForegroundColor Green

# Verify AD module installation
Write-Host "[+] Verifying AD module installation..." -ForegroundColor Cyan
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Where-Object State -eq "Installed"

# Winget Package Installation
$wingetPackages = @(
    "Ngrok.Ngrok","WireGuard.WireGuard", "microsoft.teams", "microsoft.azurecli", "microsoft.powertoys",
    "microsoft.powershell", "microsoft.windowsterminal", "Microsoft.Azure.StorageExplorer",
    "Microsoft.RemoteDesktopClient", "vscodium", "7zip.7zip", "PuTTY.PuTTY", "wireshark",
    "greenshot", "windirstat", "AntibodySoftware.WizTree", "google.chrome", "Mozilla.Firefox",
    "foxit.foxitreader", "vlc", "obsproject.obsstudio", "mremoteng.mremoteng",
    "famatech.advancedipscanner", "AnyDeskSoftwareGmbH.AnyDesk", "audacity.audacity",
    "Yubico.YubikeyManager", "rufus.rufus", "Robware.RVTools", "PortSwigger.BurpSuite.Professional",
    "Git.Git", "DominikReichl.KeePass", "Citrix.Workspace", "Microsoft.SQLServerManagementStudio",
    "OpenVPNTechnologies.OpenVPN", "Tenable.Nessus", "RealVNC.VNCViewer", "Apache.OpenOffice",
    "ExpressVPN.ExpressVPN", "SmartSoft.SmartFTP", "Notepad++.Notepad++", "Docker.DockerDesktop",
    "Microsoft.Sysinternals", "zap.zap", "VMware.HorizonClient", "Telerik.Fiddler.Everywhere",
    "Insecure.Nmap", "WinSCP.WinSCP", "TorProject.TorBrowser", "Microsoft.Sysinternals.PsTools",
    "Microsoft.Sysinternals.ProcessMonitor", "Microsoft.Sysinternals.ProcessExplorer",
    "Microsoft.Sysinternals.BGInfo", "Microsoft.Sqlcmd", "Microsoft.AzureDataStudio",
    "Microsoft.Azure.QuickReview", "rejetto.hfs", "Initex.Proxifier", "Postman.Postman",
    "Adobe.Acrobat.Reader.DC", "Adoptium.Temurin.11", "Microsoft.AzCopy", "Cyberduck.Cyberduck",
    "Mozilla.FirefoxESR", "HeidiSQL.HeidiSQL", "mh.hxd", "KiTTY.KiTTY", "Kubernetes.kubectl",
    "NirSoft.NirLauncher", "Terminals.Terminals", "Microsoft.VisualStudioCode",
    "Amazon.AWSCLI", "angryziber.AngryIPScanner", "Microsoft.VisualStudio.2022.Community","Eziriz.DotNetReactor"
)

Write-Host "`n[+] Installing packages via winget..." -ForegroundColor Cyan
foreach ($package in $wingetPackages) {
    try {
        Write-Host "[>] Installing $($package)..." -ForegroundColor White
        winget install $package --accept-source-agreements -e --accept-package-agreements
        Write-Host "[OK] $($package) installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "[X] Error installing $($package): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Install Visual Studio workloads
Write-Host "`n[+] Installing Visual Studio 2022 workloads..." -ForegroundColor Cyan
try {
    winget install Microsoft.VisualStudio.2022.Community --override "--add Microsoft.VisualStudio.Workload.NativeDesktop --add Microsoft.VisualStudio.Workload.ManagedDesktop --add Microsoft.VisualStudio.Workload.NetWeb --add Microsoft.VisualStudio.Workload.NetCrossPlat --add Microsoft.VisualStudio.Component.VC.140 --add Microsoft.VisualStudio.ComponentGroup.NativeDesktop.WinXP --add Microsoft.Net.Component.3.5.DeveloperTools --add Microsoft.VisualStudio.Component.MSBuild --includeRecommended --quiet --norestart"
    Write-Host "[OK] Visual Studio workloads installed." -ForegroundColor Green
Write-Host "[+] Installing standalone Build Tools for Visual Studio..." -ForegroundColor Cyan
winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.140 --add Microsoft.Net.Component.3.5.DeveloperTools --add Microsoft.VisualStudio.Component.MSBuild --quiet --norestart"
Write-Host "[OK] Standalone Build Tools installed." -ForegroundColor Green
} catch {
    Write-Host "[X] Failed to install Visual Studio workloads." -ForegroundColor Red
}

# Refresh environment variables
Write-Host "`n[+] Refreshing environment variables..." -ForegroundColor Cyan
[Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH", "Machine"), "Machine")
[Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH", "User"), "User")
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
Write-Host "[OK] Environment variables refreshed." -ForegroundColor Green

# Tools Folder Management
$toolsFolder = "C:\tools"
Write-Host "`n[+] Preparing tools folder..." -ForegroundColor Cyan
try {
    if (Test-Path $toolsFolder) {
        Write-Host "[>] Removing existing $toolsFolder..." -ForegroundColor Yellow
        Remove-Item -Path $toolsFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $toolsFolder | Out-Null
    Add-MpPreference -ExclusionPath $toolsFolder
    Write-Host "[OK] Tools folder ready and Defender exclusion added." -ForegroundColor Green
} catch {
    Write-Error "[X] Failed to prepare tools folder or set exclusion."
}

# Clone Repositories
Write-Host "`n[+] Cloning GitHub repositories..." -ForegroundColor Cyan
cd $toolsFolder
$repos = @(
    "PowerShellMafia/PowerSploit", "GhostPack/Rubeus", "GhostPack/Seatbelt",
    "GhostPack/Certify", "rebootuser/LinEnum", "carlospolop/PEASS-ng", "bitsadmin/wesng",
    "antonioCoco/RemotePotato0", "GhostPack/SharpUp", "danielbohannon/Invoke-Obfuscation",
    "BeichenDream/GodPotato", "ohpe/juicy-potato", "itm4n/PrintSpoofer", "TheWover/donut",
    "decoder-it/psgetsystem", "edernucci/identity-to-hashcat", "gentilkiwi/mimikatz",
    "GhostPack/KeeThief", "gentilkiwi/kekeo", "leoloobeek/LAPSToolkit", "p0dalirius/Coercer",
    "ropnop/kerbrute", "lgandx/PCredz", "SnaffCon/Snaffler", "Sw4mpf0x/PowerLurk",
    "dirkjanm/krbrelayx", "fortra/nanodump", "AlessandroZ/LaZagne", "BloodHoundAD/SharpHound",
    "t3l3machus/hoaxshell", "dafthack/GraphRunner", "OmerYa/Invisi-Shell",
    "NetSPI/PowerHuntShares", "synacktiv/GPOddity", "RythmStick/AMSITrigger",
    "cybersectroll/TrollAMSI", "cobbr/SharpSploit", "Leo4j/Find-LocalAdminAccess",
    "Leo4j/Invoke-SessionHunter", "Leo4j/Token-Impersonation", "Leo4j/Invoke-ShareHunter",
    "Leo4j/PassSpray", "danielmiessler/SecLists"."Leo4j/CheckReachableHosts","Leo4j/Invoke-SMBRemoting","Kevin-Robertson/Inveigh","paulkwalton/thescriptvault"

)
foreach ($repo in $repos) {
    Write-Host "[>] Cloning $repo..." -ForegroundColor White
    git clone "https://github.com/$repo.git" 2>$null
}

# Download additional tools
Write-Host "[+] Downloading standalone tools..." -ForegroundColor Cyan
Invoke-WebRequest -Uri 'https://hashcat.net/files/hashcat-6.2.6.7z' -OutFile 'C:\tools\hashcat-6.2.6.7z'
Invoke-WebRequest -Uri 'https://github.com/projectdiscovery/nuclei/releases/download/v3.4.2/nuclei_3.4.2_windows_amd64.zip' -OutFile 'C:\tools\nuclei_3.4.2_windows_amd64.zip'

# Install Metasploit Framework MSI
Write-Host "[+] Installing Metasploit Framework..." -ForegroundColor Cyan

$msfDownloadURL = "https://windows.metasploit.com/metasploitframework-latest.msi"
$msfDownloadLocation = "C:\tools\Metasploit"
$msfInstaller = "$msfDownloadLocation\metasploit.msi"
$msfInstallLocation = "C:\tools\metasploit"
$msfLogLocation = "$msfDownloadLocation\install.log"

if (!(Test-Path $msfDownloadLocation)) {
    New-Item -Path $msfDownloadLocation -ItemType Directory | Out-Null
}

if (!(Test-Path $msfInstallLocation)) {
    New-Item -Path $msfInstallLocation -ItemType Directory | Out-Null
}

Invoke-WebRequest -UseBasicParsing -Uri $msfDownloadURL -OutFile $msfInstaller

Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msfInstaller`" /quiet /log `"$msfLogLocation`" INSTALLLOCATION=`"$msfInstallLocation`""
Write-Host "[OK] Metasploit Framework installed to $msfInstallLocation" -ForegroundColor Green

Write-Host "`n[✔] Script execution completed." -ForegroundColor Cyan
