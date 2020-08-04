Function Invoke-Rijndael {

    <#
    .SYNOPSIS

        Invoke-Rijndael - Rijndael encryption and decryption in Powershell

        Author: Michael Schneider, scip AG
        Based on work of: Kae Travis, Alkane Solutions
                          https://www.alkanesolutions.co.uk/2015/05/20/rijndael-encryption-and-decryption-in-c-and-powershell/ 
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None


    .DESCRIPTION

        Invoke-Rijndael encrypts/decrypts files with Rijndael encryption.

    
    .PARAMETER InputFile

        File to be processed


    .PARAMETER Function

        Defines which operation is performed with the input file


    .PARAMETER OutputFile

        Path to the file where the output is saved
         
  
    .EXAMPLE
        
        Invoke-Rijndael -Function Encrypt -InputFile C:\tmp\accesschk64.exe -OutputFile C:\tmp\accesschk64.exe.txt

    #>

    [CmdletBinding()]
    Param (

        # Path to input file, will be validated
        [Parameter(ParameterSetName = 'InputFile',
            Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [String]
        $InputFile,

        # Choose your function
        [Parameter(Mandatory=$true)]
        [ValidateSet("Encrypt","Decrypt")]
        [String]
        $Function,
        
        # Path to output file, will not be validated
        # If the file does not exist, it is created
        [String]
        $OutputFile        
    )

    #
    # Global Variables
    #
    # $string is the string to encrypt, $Passphrase is a second security "password" that has to be passed to decrypt. 
    # $Salt is used during the generation of the crypto password to prevent password guessing. 
    # $Init is used to compute the crypto hash -- a checksum of the encryption 
    #
    $Passphrase = "gcHyqwHfLdNAxkn4csALdCyBL30BbeXSxfMrjnmwmk5CtWhOh8QQsuYtbc3ebHz9"
    $Salt = "rkCkBbcFtgbnDuXILk4Xb7Pjh2g6FUWMrGBKA3Bbi6aXc4bbSGKxPU2rEjxjWkSb"
    $Init = "WdajOdIiKNt5373biyP11X1TVDG3omFDjGXHP96SQkU4olUvtcAmGBxEFJEHLkKL"
     
    Function Encrypt-String($String, [switch]$arrayOutput) {

        # Create a COM Object for RijndaelManaged Cryptography 
        $r = new-Object System.Security.Cryptography.RijndaelManaged 
        # Convert the Passphrase to UTF8 Bytes 
        $pass = [Text.Encoding]::UTF8.GetBytes($Passphrase) 
        # Convert the Salt to UTF Bytes 
        $Salt = [Text.Encoding]::UTF8.GetBytes($Salt) 
 
        # Create the Encryption Key using the Passphrase, salt and SHA1 algorithm at 256 bits 
        $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $Salt, "SHA1", 5).GetBytes(32) #256/8 
        # Create the Intersecting Vector Cryptology Hash with the init 
        $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($Init) )[0..15] 
     
        # Starts the New Encryption using the Key and IV    
        $c = $r.CreateEncryptor() 
        # Creates a MemoryStream to do the encryption in 
        $ms = new-Object IO.MemoryStream 
        # Creates the new Cryptology Stream --> Outputs to $MS or Memory Stream 
        $cs = new-Object Security.Cryptography.CryptoStream $ms,$c,"Write" 
        # Starts the new Cryptology Stream 
        $sw = new-Object IO.StreamWriter $cs 
        # Writes the string in the Cryptology Stream 
        $sw.Write($String) 
        # Stops the stream writer 
        $sw.Close() 
        # Stops the Cryptology Stream 
        $cs.Close() 
        # Stops writing to Memory 
        $ms.Close() 
        # Clears the IV and HASH from memory to prevent memory read attacks 
        $r.Clear() 
        # Takes the MemoryStream and puts it to an array 
        [byte[]]$result = $ms.ToArray() 
        # Converts the array from Base 64 to a string and returns 
        return [Convert]::ToBase64String($result) 
    } 
 
    function Decrypt-String($Encrypted) {

        # If the value in the Encrypted is a string, convert it to Base64 
        if($Encrypted -is [string]){ 
            $Encrypted = [Convert]::FromBase64String($Encrypted)        
        } 
 
        # Create a COM Object for RijndaelManaged Cryptography 
        $r = new-Object System.Security.Cryptography.RijndaelManaged 
        # Convert the Passphrase to UTF8 Bytes 
        $pass = [Text.Encoding]::UTF8.GetBytes($Passphrase) 
        # Convert the Salt to UTF Bytes 
        $Salt = [Text.Encoding]::UTF8.GetBytes($Salt) 
 
        # Create the Encryption Key using the Passphrase, salt and SHA1 algorithm at 256 bits 
        $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $Salt, "SHA1", 5).GetBytes(32) #256/8 
        # Create the Intersecting Vector Cryptology Hash with the init 
        $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($Init) )[0..15] 
 
 
        # Create a new Decryptor 
        $d = $r.CreateDecryptor() 
        # Create a New memory stream with the encrypted value. 
        $ms = new-Object IO.MemoryStream @(,$Encrypted) 
        # Read the new memory stream and read it in the cryptology stream 
        $cs = new-Object Security.Cryptography.CryptoStream $ms,$d,"Read" 
        # Read the new decrypted stream 
        $sr = new-Object IO.StreamReader $cs 
        # Return from the function the stream 
        Write-Output $sr.ReadToEnd() 
        # Stops the stream     
        $sr.Close() 
        # Stops the crypology stream 
        $cs.Close() 
        # Stops the memory stream 
        $ms.Close() 
        # Clears the RijndaelManaged Cryptology IV and Key 
        $r.Clear() 
    }

    Switch ($Function) {
        "Encrypt" { $InputString = Get-Content $InputFile -Raw; $OutputString = Encrypt-String $InputString }
        "Decrypt" { $InputString = Get-Content $InputFile -Raw; $OutputString = Decrypt-String $InputString }    
    }

    $OutputString | Set-Content $OutputFile
}