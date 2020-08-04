Function Invoke-Base64 {

    <#
    .SYNOPSIS

        Invoke-Base64 - Basic Base64 functions

        Author: Michael Schneider, scip AG
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None


    .DESCRIPTION

        Invoke-Base64 includes basic functions to encode/decode text
        and files, and execute Base64 encoded text.

    
    .PARAMETER InputFile

        File to be processed, cannot be used with InputText 


    .PARAMETER InputText

        String to be processed, cannot be used with InputFile


    .PARAMETER Function

        Defines which operation is performed with the input


    .PARAMETER OutputFile

        Path to the file where the output is saved
         
   
    .EXAMPLES
        
        Invoke-Base64 -Function Encode -InputFile C:\tmp\accesschk64.exe -OutputFile .\test.txt

        Invoke-Base64 -Function Encode -InputText "Write-Host 'Hello World'"

        Invoke-Base64 -Function Execute -InputText VwByAGkAdABlAC0ASABvAHMAdAAgACcARABvACAAbgBvAHQAIAByAHUAbgAgAGMAbwBkAGUAIABmAHIAbwBtACAAdABoAGUAIABpAG4AdABlAHIAbgBlAHQAJwA=

    #>

    [CmdletBinding(DefaultParameterSetName='InputFile')]
    Param (

        # Path to input file, will be validated
        [Parameter(ParameterSetName = 'InputFile',
            Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [String]
        $InputFile,

        # Input text, cannot be used with InputFile
        [Parameter(ParameterSetName = 'InputText',
            Mandatory = $true)]
        [String]
        $InputText,

        # Choose your function
        [Parameter(Mandatory=$true)]
        [ValidateSet("Decode","Encode", "Execute")]
        [String]
        $Function,
        
        # Path to output file, will not be validated
        # If the file does not exist, it is created
        [String]
        $OutputFile        
    )

    Function Base64Encode {

        <#
        .SYNOPSIS
    
            Encode text or a file into Base64, the unicode character set (UTF-16LE)
            is used to make the output compatible with the built-in Base64
            function in PowerShell (-enc).
        #>

        #
        # Input processing
        #
        If ($InputText.Length -gt 0) {        
            $InputEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($InputText))            
        }
        ElseIf ($InputFile.Length -gt 0) {

            try {
                $InputEncoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($InputFile))
            } catch [System.IO.FileNotFoundException] {
                $CurrentPath = Get-Location
                $InputFile = $CurrentPath.Path+"\$InputFile"
                $InputEncoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($InputFile))
            }

        }
        return $InputEncoded
    }

    Function Base64Decode {

        <#
        .SYNOPSIS
    
            Decode a Base64 text or file into plaintext again, 
            the unicode character set (UTF-16LE) is used.
        #>
    
        #
        # Input processing
        #    
        If ($InputText.Length -gt 0) {
            $InputDecoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($InputText))
            $InputDecoded
        }
        ElseIf ($InputFile.Length -gt 0) {
            $InputFileRaw = Get-Content -Raw $InputFile
            $InputDecoded = [IO.File]::WriteAllBytes($OutputFile, [Convert]::FromBase64String($InputFileRaw))
        }
    }

    Function Output ([String] $OutputContent) {

        <#
        .SYNOPSIS
    
            Function to write output to a file.
        #>

        If ($OutputFile.Length -gt 0) {
            $OutputContent | Set-Content $OutputFile      
        }
        Else {
            $OutputContent
        }
    }

    Function Execute ([String] $Commands) {

        <#
        .SYNOPSIS
    
            Function to start PowerShell and execute Base64 input.
        #>

        powershell -ExecutionPolicy ByPass -Enc $Commands    
    }

    Switch ($Function) {
        "Encode" { Output(Base64Encode) }
        "Decode" { Base64Decode }
        "Execute" { Execute($InputText) }
        default { Output(Base64Encode) }
    }
}