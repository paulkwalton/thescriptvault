# Windows 11 Setup Script (Azure) - Non-Domain Joined
# ------------------------------------------------------------
# Order:
#   1. Remove unwanted apps
#   2. Install tooling
#   3. Apply Windows 11 v25H2 Security Baseline (-Win11NonDomainJoined)
#   4. Allow inbound RDP through firewall (after hardening)
#
# NOTE: The baseline ZIP no longer bundles LGPO.exe. LGPO.exe is now fetched only from the provided GitHub link. No other sources are attempted.
# If download fails, manually download the Security Compliance Toolkit and place LGPO.exe into:
#   <...>\Windows 11 v25H2 Security Baseline\Scripts\Tools\LGPO.exe

function Remove-UnwantedApps {
    Write-Host "`n[+] Removing unwanted Windows apps..." -ForegroundColor Cyan
    $bloatwareApps = @(
        "Microsoft.ZuneMusic","Microsoft.ZuneVideo","Microsoft.WindowsMaps",
        "Microsoft.MicrosoftSolitaireCollection","Microsoft.BingWeather","Microsoft.WindowsAlarms",
        "Microsoft.WindowsCamera","Microsoft.GetHelp","Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub","Microsoft.Microsoft3DViewer","Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay","Microsoft.XboxGamingOverlay","Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay","Microsoft.MixedReality.Portal","Microsoft.People",
        "Microsoft.SkypeApp","Microsoft.MicrosoftStickyNotes","Microsoft.YourPhone",
        "Microsoft.OneConnect","Microsoft.Todos"
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

function Allow-RDP-InboundFirewall {
    Write-Host "`n[+] Allowing inbound RDP through Windows Firewall..." -ForegroundColor Cyan
    try {
        # Enable Remote Desktop (if not already enabled)
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop

        # Add inbound firewall rule for RDP (TCP 3389)
        New-NetFirewallRule -DisplayName "Allow RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Domain,Private,Public -ErrorAction Stop
        Write-Host "[OK] Inbound RDP allowed in firewall." -ForegroundColor Green
    }
    catch {
        Write-Host "[X] Failed to allow inbound RDP: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Install-WindowsSecurityBaselineNonDomainJoined {
    param(
        [string]$DownloadRoot = [IO.Path]::Combine($env:USERPROFILE, 'Downloads'),
        [switch]$ForceRedownload
    )
    Write-Host "`n[+] Applying Windows 11 v25H2 Security Baseline (Non-Domain Joined)..." -ForegroundColor Cyan

    $baselineZipUrl  = "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    $baselineZip     = Join-Path $DownloadRoot "Windows11_v25H2_Baseline.zip"
    $extractPath     = Join-Path $DownloadRoot "Windows11_v25H2_Baseline_Extracted"

    try {
        if ($ForceRedownload -or -not (Test-Path $baselineZip)) {
            Write-Host "[*] Downloading baseline ZIP..." -ForegroundColor DarkCyan
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $baselineZipUrl -OutFile $baselineZip -UseBasicParsing
        } else {
            Write-Host "[*] Baseline ZIP already present. (Use -ForceRedownload to fetch again.)" -ForegroundColor DarkCyan
        }

        Write-Host "[*] Extracting baseline to: $extractPath" -ForegroundColor DarkCyan
        if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
        Expand-Archive -Path $baselineZip -DestinationPath $extractPath

        Write-Host "[*] Locating Baseline-LocalInstall.ps1..." -ForegroundColor DarkCyan
        $baselineScript = Get-ChildItem -Path $extractPath -Filter "Baseline-LocalInstall.ps1" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $baselineScript) { throw "Baseline-LocalInstall.ps1 not found." }

        $scriptsDir = $baselineScript.DirectoryName
        Write-Host "[OK] Found baseline script at: $scriptsDir" -ForegroundColor Green

        # Ensure Tools folder and LGPO.exe
        $toolsDir = Join-Path $scriptsDir "Tools"
        if (-not (Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir | Out-Null }
        $lgpoExePath = Join-Path $toolsDir "LGPO.exe"

        # --- AMENDED LOGIC: Always download LGPO.exe from the provided GitHub URL; do not try other sources ---
        if (-not (Test-Path $lgpoExePath)) {
            Write-Host "[*] LGPO.exe not present. Attempting to download from provided URL..." -ForegroundColor DarkCyan
            $directLgpoUrl = "https://github.com/paulkwalton/thescriptvault/raw/refs/heads/main/build/LGPO.exe"
            try {
                Invoke-WebRequest -Uri $directLgpoUrl -OutFile $lgpoExePath -UseBasicParsing -ErrorAction Stop
                if ((Test-Path $lgpoExePath) -and ((Get-Item $lgpoExePath).Length -gt 40KB)) {
                    Write-Host "[OK] LGPO.exe acquired from provided URL." -ForegroundColor Green
                } else {
                    Write-Host "[X] LGPO.exe download failed or file too small." -ForegroundColor Red
                    Write-Host "    Manual fix: Download Security Compliance Toolkit and place LGPO.exe in:" -ForegroundColor Red
                    Write-Host "    $toolsDir" -ForegroundColor Red
                    return
                }
            }
            catch {
                Write-Host "[X] LGPO.exe download from provided URL failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "    Manual fix: Download Security Compliance Toolkit and place LGPO.exe in:" -ForegroundColor Red
                Write-Host "    $toolsDir" -ForegroundColor Red
                return
            }
        } else {
            Write-Host "[OK] LGPO.exe already present." -ForegroundColor Green
        }
        # --- End amended logic ---

        Get-ChildItem -Path $scriptsDir -Recurse | Unblock-File -ErrorAction SilentlyContinue

        Write-Host "[*] Executing baseline script with -Win11NonDomainJoined ..." -ForegroundColor DarkCyan
        Push-Location $scriptsDir
        try {
            & $baselineScript.FullName -Win11NonDomainJoined -ErrorAction Stop
            Write-Host "[OK] Baseline applied successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "[X] Baseline script failed: $($_.Exception.Message)" -ForegroundColor Red
            if ($_.InvocationInfo) {
                Write-Host "    At: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
            }
            Write-Host "    Confirm LGPO.exe is at: $lgpoExePath" -ForegroundColor Yellow
            return
        }
        finally {
            Pop-Location -ErrorAction SilentlyContinue
        }

        Write-Host "[+] Baseline application finished. Reboot is recommended." -ForegroundColor Yellow
    }
    catch {
        Write-Host "[X] Unexpected failure: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# -------------------------
# Main Execution
# -------------------------
Remove-UnwantedApps

# Tooling Installation
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

# Apply baseline hardening LAST (will reboot)
Install-WindowsSecurityBaselineNonDomainJoined

# Re-enable inbound RDP through firewall after hardening
Allow-RDP-InboundFirewall

Write-Host "`n[+] Script finished. Reboot recommended if baseline just applied." -ForegroundColor Yellow
