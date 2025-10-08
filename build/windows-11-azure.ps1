# 2. CONFIGURE SYSTEM SETTINGS
# -------------------------------------------------------------------
Write-Host "`n[+] Disabling firewalls and configuring system settings..." -ForegroundColor Cyan
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False -ErrorAction Stop
    # Set power scheme to 'High performance'
    powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    # Enable Remote Desktop connections
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
    Write-Host "[OK] Firewall, power, and RDP settings updated." -ForegroundColor Green
}
catch {
    Write-Host "[X] Failed to configure system settings: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. INSTALL ACTIVE DIRECTORY (RSAT) MODULES
# -------------------------------------------------------------------
Write-Host "`n[+] Installing Active Directory modules..." -ForegroundColor Cyan
try {
    Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online -ErrorAction Stop
    Write-Host "[OK] AD modules installation command sent." -ForegroundColor Green
    # Verify installation
    Write-Host "[+] Verifying AD module installation..." -ForegroundColor Cyan
    Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Where-Object State -eq "Installed"
}
catch {
    Write-Host "[X] Failed to install AD Modules: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. DEFINE WINGET PACKAGES
# -------------------------------------------------------------------
# This list is formatted for clarity and easy editing.
$wingetPackages = @(
    "7zip.7zip",
    "Apache.OpenOffice",
    "Citrix.Workspace",
    "Cyberduck.Cyberduck",
    "Docker.DockerDesktop",
    "DominikReichl.KeePass",
    "Git.Git",
    "Google.Chrome",
    "Greenshot.Greenshot",
    "HeidiSQL.HeidiSQL",
    "Insecure.Nmap",
    "Initex.Proxifier",
    "KiTTY.KiTTY",
    "Kubernetes.kubectl",
    "mh.hxd",
    "Microsoft.Azure.StorageExplorer",
    "Microsoft.AzureCLI",
    "Microsoft.AzureDataStudio",
    "Microsoft.AzCopy",
    "Microsoft.PowerShell",
    "Microsoft.PowerToys",
    "Microsoft.RemoteDesktopClient",
    "Microsoft.SQLServerManagementStudio",
    "Microsoft.Sqlcmd",
    "Microsoft.Sysinternals.SysinternalsSuite",
    "Microsoft.WindowsTerminal",
    "Mozilla.FirefoxESR",
    "Notepad++.Notepad++",
    "PortSwigger.BurpSuite.Professional",
    "PuTTY.PuTTY",
    "RealVNC.VNCViewer",
    "rejetto.hfs",
    "Robware.RVTools",
    "Rufus.Rufus",
    "SmartSoft.SmartFTP",
    "Tenable.Nessus",
    "Terminals.Terminals",
    "TorProject.TorBrowser",
    "VSCodium.VSCodium",
    "Wireshark.Wireshark",
    "WinDirStat.WinDirStat",
    "WinSCP.WinSCP",
    "Yubico.YubikeyManager"
)

# 5. INSTALL PACKAGES VIA WINGET
# -------------------------------------------------------------------
Write-Host "`n[+] Installing $($wingetPackages.Count) packages via winget..." -ForegroundColor Cyan
foreach ($package in $wingetPackages) {
    Write-Host "[>] Attempting to install: $($package)..." -ForegroundColor White
    
    # Use --id to be specific and --silent to prevent installers from hanging the script.
    winget install --id $package --silent --accept-source-agreements --accept-package-agreements

    # Check the exit code of the last command. 0 typically means success.
    # This is more reliable than try/catch for external programs like winget.
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Successfully installed $($package)." -ForegroundColor Green
    } else {
        Write-Host "[X] Error installing $($package). Winget exited with code: $LASTEXITCODE" -ForegroundColor Red
    }
}

Write-Host "`n[+] Script finished." -ForegroundColor Yellow
