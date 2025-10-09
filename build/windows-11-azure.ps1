# Windows 11 Setup Script (Azure) - Non-Domain Joined
# ------------------------------------------------------------
# Order:
#   1. Apply Windows 11 v25H2 Security Baseline (-Win11NonDomainJoined)
#   2. Remove unwanted apps
#   3. (Optional) Disable firewall & tweak system (undoes some baseline protections)
#   4. Install tooling
#
# NOTE: The baseline ZIP no longer bundles LGPO.exe. We attempt several known URLs.
# If all fail, manually download the Security Compliance Toolkit and place LGPO.exe into:
#   <...>\Windows 11 v25H2 Security Baseline\Scripts\Tools\LGPO.exe

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

        if (-not (Test-Path $lgpoExePath)) {
            Write-Host "[*] LGPO.exe not present. Attempting download..." -ForegroundColor DarkCyan
            $candidateLgpoUrls = @(
                # Known historical direct download links for LGPO
                "https://download.microsoft.com/download/2/8/5/2857D59E-0B4E-4D4A-9C0D-6D1D03C0C6B8/LGPO.zip",
                "https://download.microsoft.com/download/7/F/5/7F5DC3B5-DA5A-4969-9BB0-51B7427F7E70/LGPO.zip",
                "https://aka.ms/lgpo"
            )
            $lgpoAcquired = $false
            $tempLgpoDir = Join-Path $toolsDir "LGPO_Download"
            if (Test-Path $tempLgpoDir) { Remove-Item $tempLgpoDir -Recurse -Force }
            New-Item -ItemType Directory -Path $tempLgpoDir | Out-Null

            foreach ($url in $candidateLgpoUrls) {
                Write-Host "    -> Trying: $url" -ForegroundColor Gray
                $zipCandidate = Join-Path $tempLgpoDir "LGPO.zip"
                try {
                    Invoke-WebRequest -Uri $url -OutFile $zipCandidate -UseBasicParsing -ErrorAction Stop
                    if ((Get-Item $zipCandidate).Length -lt 40KB) {
                        Write-Host "       Download too small, skipping." -ForegroundColor Yellow
                        continue
                    }
                    Expand-Archive -Path $zipCandidate -DestinationPath $tempLgpoDir -Force -ErrorAction Stop
                    $found = Get-ChildItem -Path $tempLgpoDir -Filter "LGPO.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($found) {
                        Copy-Item $found.FullName $lgpoExePath -Force
                        Write-Host "[OK] LGPO.exe acquired." -ForegroundColor Green
                        $lgpoAcquired = $true
                        break
                    } else {
                        Write-Host "       LGPO.exe not inside archive." -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "       Failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }

            if (-not $lgpoAcquired) {
                Write-Host "[X] Could not automatically retrieve LGPO.exe." -ForegroundColor Red
                Write-Host "    Manual fix: Download Security Compliance Toolkit and place LGPO.exe in:" -ForegroundColor Red
                Write-Host "    $toolsDir" -ForegroundColor Red
                return
            }
        } else {
            Write-Host "[OK] LGPO.exe already present." -ForegroundColor Green
        }

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

function Disable-Firewall-And-Configure-System {
    Write-Host "`n[+] Disabling firewalls and configuring system settings..." -ForegroundColor Cyan
    Write-Host "[!] This undoes firewall protections from the security baseline. Remove this call to keep them." -ForegroundColor Magenta
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False -ErrorAction Stop
        powercfg /s SCHEME_MIN
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
        Write-Host "[OK] Firewall disabled; power plan set; RDP enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "[X] Failed to configure system settings: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# -------------------------
# Main Execution
# -------------------------
Install-WindowsSecurityBaselineNonDomainJoined
Remove-UnwantedApps
Disable-Firewall-And-Configure-System   # Comment/remove to retain firewall from baseline

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

Write-Host "`n[+] Script finished. Reboot recommended if baseline just applied." -ForegroundColor Yellow
