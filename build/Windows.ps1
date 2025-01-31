# Winget Package Installation

$wingetPackages = @(
    "microsoft.teams", "microsoft.azurecli", "microsoft.powertoys", "microsoft.powershell",
    "microsoft.windowsterminal", "microsoft.azurestorageexplorer", "Microsoft.RemoteDesktopClient",
    "vscodium", "7zip.7zip", "putty.putty", "wireshark", "winscp", "greenshot", "windirstat",
    "AntibodySoftware.WizTree", "google.chrome", "Mozilla.Firefox", "foxit.foxitreader", "vlc",
    "obsproject.obsstudio", "mremoteng.mremoteng", "famatech.advancedipscanner", "AnyDeskSoftwareGmbH.AnyDesk",
    "audacity.audacity", "Yubico.YubikeyManager", "rufus.rufus", "Robware.RVTools",
    "PortSwigger.BurpSuite.Professional", "Git.Git", "DominikReichl.KeePass", "Citrix.Workspace",
    "Microsoft.SQLServerManagementStudio", "OpenVPNTechnologies.OpenVPN", "Tenable.Nessus",
    "RealVNC.VNCViewer", "Apache.OpenOffice", "ExpressVPN.ExpressVPN", "SmartSoft.SmartFTP",
    "Notepad++.Notepad++", "Docker.DockerDesktop", "Eziriz.DotNetReactor",
    "Microsoft.VisualStudio.2022.Community.Preview", "Microsoft.Sysinternals", "zap.zap",
    "VMware.HorizonClient", "Telerik.Fiddler.Everywhere", "Insecure.Nmap", "WinSCP.WinSCP",
    "TorProject.TorBrowser", "Microsoft.Sysinternals.PsTools", "Microsoft.Sysinternals.ProcessMonitor",
    "Microsoft.Sysinternals.ProcessExplorer", "Microsoft.Sysinternals.BGInfo", "Microsoft.Sqlcmd",
    "Microsoft.AzureDataStudio", "Microsoft.Azure.StorageExplorer", "Microsoft.Azure.QuickReview","Docker.DockerDesktop","rejetto.hfs","Initex.Proxifier")

# Install each package, handling errors individually
foreach ($package in $wingetPackages) {
    try {
        Write-Host "Installing $($package)..."
        winget install $package --accept-source-agreements -e --accept-package-agreements
        Write-Host "$($package) installed successfully."
    }
    catch {
        Write-Error "Error installing $($package): $($_.Exception.Message)"
    }
}

# Refresh environment variables
Write-Host "Refreshing environment variables..."
[Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH", "Machine"), "Machine")
[Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH", "User"), "User")
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")

# Tools Folder Management
$toolsFolder = "C:\tools"

# --- Delete and Recreate C:\tools ---
try {
    Write-Host "Removing existing tools folder $($toolsFolder)..."
    Remove-Item -Path $toolsFolder -Recurse -Force -ErrorAction SilentlyContinue 

    Write-Host "Creating tools folder: $($toolsFolder)..."
    New-Item -ItemType Directory -Path $toolsFolder

    # Add Windows Defender exclusion
    Add-MpPreference -ExclusionPath $toolsFolder
    Write-Host "Added Windows Defender exclusion for $($toolsFolder)."
}
catch {
    Write-Error "Failed to manage tools folder or add Defender exclusion. Ensure you're running as administrator."
}

# --- Git Clone Operations (Simplified to the Extreme) ---
Write-Host "Cloning repositories into $($toolsFolder)..."

cd $toolsFolder

# No loops, just direct git clone commands, no error handling:
$env:GIT_REDIRECT_STDERR = '2>&1'
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/GhostPack/Rubeus.git
git clone https://github.com/GhostPack/Seatbelt.git
git clone https://github.com/GhostPack/Certify.git
git clone https://github.com/rebootuser/LinEnum.git
git clone https://github.com/carlospolop/PEASS-ng.git 
git clone https://github.com/bitsadmin/wesng.git
git clone https://github.com/antonioCoco/RemotePotato0.git
git clone https://github.com/carlospolop/PEASS-ng.git
git clone https://github.com/GhostPack/SharpUp.git
git clone https://github.com/danielbohannon/Invoke-Obfuscation.git
git clone https://github.com/BeichenDream/GodPotato.git
git clone https://github.com/ohpe/juicy-potato.git
git clone https://github.com/itm4n/PrintSpoofer.git
git clone https://github.com/TheWover/donut.git
git clone https://github.com/decoder-it/psgetsystem.git
git clone https://github.com/OneLogicalMyth/BuildReview-Windows.git
git clone https://github.com/OneLogicalMyth/PAudit.git
git clone https://github.com/edernucci/identity-to-hashcat.git
git clone https://github.com/gentilkiwi/mimikatz.git
git clone https://github.com/GhostPack/KeeThief.git
git clone https://github.com/gentilkiwi/kekeo.git
git clone https://github.com/leoloobeek/LAPSToolkit.git
git clone https://github.com/p0dalirius/Coercer.git
git clone https://github.com/ropnop/kerbrute.git
git clone https://github.com/lgandx/PCredz.git
git clone https://github.com/SnaffCon/Snaffler.git
git clone https://github.com/Sw4mpf0x/PowerLurk.git
git clone https://github.com/dirkjanm/krbrelayx.git
git clone https://github.com/fortra/nanodump.git
git clone https://github.com/sc0tfree/updog.git
git clone https://github.com/ITI/ICS-Security-Tools.git
git clone https://github.com/AlessandroZ/LaZagne.git
git clone https://github.com/BloodHoundAD/SharpHound.git
git clone https://github.com/t3l3machus/hoaxshell.git
git clone https://github.com/dafthack/GraphRunner.git
git clone https://github.com/OmerYa/Invisi-Shell.git
git clone https://github.com/NetSPI/PowerHuntShares.git
git clone https://github.com/itm4n/PrivescCheck.git

Invoke-WebRequest -Uri 'https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip' -OutFile 'C:\tools\PingCastle_3.3.0.1.zip'


Write-Host "Script execution completed." 
