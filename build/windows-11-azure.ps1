# Refactored Windows Setup Script
# ---------------------------------------------

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
Test-Admin
Disable-Firewall-And-Configure-System
winget install -e --id Iterate.Cyberduck
winget install -e --id Tenable.Nessus
winget install -e --id PortSwigger.BurpSuite.Professional
winget install -e --id Insecure.Nmap
winget install -e --id WiresharkFoundation.Wireshark
winget install -e --id Docker.DockerDesktop

winget install -e --id Microsoft.AzureDataStudio
winget install -e --id Microsoft.Azure.StorageExplorer
winget install -e --id Microsoft.AzureCLI

Write-Host "`n[+] Script finished." -ForegroundColor Yellow
