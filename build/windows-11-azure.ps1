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
    "microsoft.azurecli", "microsoft.powertoys", "microsoft.powershell", "microsoft.windowsterminal", "Microsoft.Azure.StorageExplorer", "Microsoft.RemoteDesktopClient", "vscodium", "7zip.7zip", "PuTTY.PuTTY", "wireshark", "greenshot", "windirstat","google.chrome", "Yubico.YubikeyManager", "rufus.rufus", "Robware.RVTools", "PortSwigger.BurpSuite.Professional", "Git.Git", "DominikReichl.KeePass", "Citrix.Workspace", "Microsoft.SQLServerManagementStudio", "Tenable.Nessus", "RealVNC.VNCViewer", "Apache.OpenOffice", "SmartSoft.SmartFTP", "Notepad++.Notepad++", "Docker.DockerDesktop", "Microsoft.Sysinternals", "Insecure.Nmap", "WinSCP.WinSCP", "TorProject.TorBrowser", "Microsoft.Sysinternals.PsTools", "Microsoft.Sysinternals.ProcessMonitor", "Microsoft.Sysinternals.ProcessExplorer", "Microsoft.Sqlcmd", "Microsoft.AzureDataStudio", "Microsoft.Azure.QuickReview", "rejetto.hfs", "Initex.Proxifier", "Microsoft.AzCopy", "Cyberduck.Cyberduck", "Mozilla.FirefoxESR", "HeidiSQL.HeidiSQL", "mh.hxd", "KiTTY.KiTTY", "Kubernetes.kubectl","Terminals.Terminals"
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

