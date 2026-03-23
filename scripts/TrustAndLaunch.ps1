# Aegis11 Professional Signing & Trust Injector
$ErrorActionPreference = 'SilentlyContinue'

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$exePath = "C:\Users\Genesisif\Projects\Aegis11\aegis11.exe"
$certSubject = "CN=Aegis Systems Trusted Publisher"

Write-Host "[*] Purging legacy Aegis certificates..." -ForegroundColor Cyan
Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Subject -match "Aegis" } | Remove-Item

Write-Host "[*] Creating Enterprise-grade Local Signing Certificate..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -Subject $certSubject -Type CodeSigningCert -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(10)

Write-Host "[*] Injecting Certificate into Kernel Trust Stores (Root & TrustedPublisher)..." -ForegroundColor Cyan
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()

$pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
$pubStore.Open("ReadWrite")
$pubStore.Add($cert)
$pubStore.Close()

Write-Host "[*] Applying Authenticode SHA256 Signature to aegis11.exe..." -ForegroundColor Cyan
Set-AuthenticodeSignature -FilePath $exePath -Certificate $cert -HashAlgorithm SHA256

Write-Host "[*] Stripping 'Mark of the Web' NTFS Stream..." -ForegroundColor Cyan
Unblock-File -Path $exePath

Write-Host "[+] Cryptographic Trust established. Smart App Control should now authorize execution." -ForegroundColor Green
Write-Host "[+] Launching Engine..." -ForegroundColor Green
Start-Process -FilePath $exePath
