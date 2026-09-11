[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Executable = (Join-Path $PSScriptRoot '..\build\Release\aegis11.exe'),
    [string]$CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
$exePath = (Resolve-Path -LiteralPath $Executable -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { throw 'Executable is not a file.' }

# Signing is optional and uses an existing certificate selected by its full
# thumbprint. Trust stores and download provenance are never modified here.
if ($CertificateThumbprint) {
    if ($CertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'A complete certificate thumbprint is required.' }
    $cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint"
    if (-not $cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date)) { throw 'Signing certificate is expired or has no private key.' }
    if ($PSCmdlet.ShouldProcess($exePath, 'Apply Authenticode signature')) {
        $result = Set-AuthenticodeSignature -LiteralPath $exePath -Certificate $cert -HashAlgorithm SHA256
        if ($result.Status -ne 'Valid') { throw "Signature verification failed: $($result.Status)" }
    }
}
$signature = Get-AuthenticodeSignature -LiteralPath $exePath
if ($signature.Status -ne 'Valid') { throw "Executable is not trusted by Windows: $($signature.Status)" }
if ($PSCmdlet.ShouldProcess($exePath, 'Launch verified executable')) {
    Start-Process -FilePath $exePath -WorkingDirectory (Split-Path -Parent $exePath)
}
