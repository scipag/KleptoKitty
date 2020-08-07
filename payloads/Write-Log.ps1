<#
     =^._.^=
    _(      )/  KleptoKitty
#>

$ProtocolPath = "C:\Windows\kleptokitty.log"

$Time = Get-Date -Format G
$Message = "$Time - Klepto Kitty was here."

Add-Content -Path $ProtocolPath -Value $Message