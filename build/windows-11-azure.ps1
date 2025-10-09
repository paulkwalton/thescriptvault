# Refactored Windows Setup Script
# ---------------------------------------------

function Remove-UnwantedApps {
    Write-Host "`n[+] Removing unwanted Windows apps..." -ForegroundColor Cyan
    $bloatwareApps = @(
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.WindowsMaps",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.BingWeather",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsCamera",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.MixedReality.Portal",
        "Microsoft.People",
        "Microsoft.SkypeApp",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.YourPhone",
        "Microsoft.OneConnect",
        "Microsoft.Todos"
    )
    foreach ($app in $bloatwareApps) {
        try {
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            Write-Host "[OK] Removed ${app}" -ForegroundColor Green
        }
        catch {
            Write-Host "[X] Failed to remove ${app}: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "[+] Bloatware removal complete." -ForegroundColor Yellow
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

# Main Script Execution
Remove-UnwantedApps
Disable-Firewall-And-Configure-System

# Suppress license prompts for each winget install using --accept-package-agreements --accept-source-agreements
winget install -e --id Iterate.Cyberduck --accept-package-agreements --accept-source-agreements
winget install -e --id Tenable.Nessus --accept-package-agreements --accept-source-agreements
winget install -e --id PortSwigger.BurpSuite.Professional --accept-package-agreements --accept-source-agreements
winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements
winget install -e --id WiresharkFoundation.Wireshark --accept-package-agreements --accept-source-agreements
winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
winget install -e --id=Microsoft.Sysinternals.Suite --accept-package-agreements --accept-source-agreements

winget install -e --id Microsoft.AzureDataStudio --accept-package-agreements --accept-source-agreements
winget install -e --id Microsoft.Azure.StorageExplorer --accept-package-agreements --accept-source-agreements
winget install -e --id Microsoft.AzureCLI --accept-package-agreements --accept-source-agreements

Write-Host "`n[+] Script finished." -ForegroundColor Yellow
