# Refactored Windows Setup Script
# ---------------------------------------------

function Test-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "[X] This script must be run as administrator." -ForegroundColor Red
        exit 1
    }
}

function Disable-Firewall-And-Configure-System {
    Write-Host "`n[+] Disabling firewalls and configuring system settings..." -ForegroundColor Cyan
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False -ErrorAction Stop
        powercfg /s SCHEME_MIN
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
        Write-Host "[OK] Firewall, power, and RDP settings updated." -ForegroundColor Green
    }
    catch {
        Write-Host "[X] Failed to configure system settings: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-Winget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "[X] winget is not installed or not in PATH." -ForegroundColor Red
        exit 1
    }
}

function Install-Winget-Packages {
    param([string[]]$Packages)
    Write-Host "`n[+] Installing $($Packages.Count) packages via winget..." -ForegroundColor Cyan
    foreach ($package in $Packages) {
        Write-Host "[>] Attempting to install: $($package)..." -ForegroundColor White
        $alreadyInstalled = winget list --id $package | Select-String $package
        if ($alreadyInstalled) {
            Write-Host "[OK] $($package) is already installed." -ForegroundColor Yellow
            continue
        }
        winget install --id $package --silent --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Successfully installed $($package)." -ForegroundColor Green
        } else {
            Write-Host "[X] Error installing $($package). Winget exited with code: $LASTEXITCODE" -ForegroundColor Red
        }
    }
}

# Main Script Execution
Test-Admin
Disable-Firewall-And-Configure-System
Test-Winget

$wingetPackages = @(
    "Cyberduck.Cyberduck",
    "Docker.DockerDesktop",
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
    "Microsoft.SQLServerManagementStudio",
    "Microsoft.Sqlcmd",
    "Microsoft.Sysinternals.SysinternalsSuite",
    "Microsoft.WindowsTerminal",
    "PortSwigger.BurpSuite.Professional",
    "PuTTY.PuTTY",
    "RealVNC.VNCViewer",
    "rejetto.hfs",
    "Robware.RVTools",
    "Rufus.Rufus",
    "SmartSoft.SmartFTP",
    "Tenable.Nessus",
    "Terminals.Terminals",
    "Wireshark.Wireshark",
    "WinDirStat.WinDirStat",
    "WinSCP.WinSCP"
)

Install-Winget-Packages -Packages $wingetPackages

Write-Host "`n[+] Script finished." -ForegroundColor Yellow
