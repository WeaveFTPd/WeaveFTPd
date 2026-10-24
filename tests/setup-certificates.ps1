param([string]$SetupScript, [string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path $SetupScript), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw $errors[0] }
# Load only the certificate helper and its utility functions. Never run the
# installer's top-level commands or touch an existing installation.
foreach ($name in @('Say', 'Ensure-Dir', 'Write-Utf8NoBom', 'Assert-NativeSuccess', 'Generate-CertsWithGo')) {
    $node = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $node) { throw "Missing installer function $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$ToolsDir = Join-Path $OutputDirectory 'tools'
$certDir = Join-Path $OutputDirectory 'certs'
Generate-CertsWithGo (Get-Command go).Source $certDir 'LOCAL'
$ca = New-Object Security.Cryptography.X509Certificates.X509Certificate2((Join-Path $certDir 'ca.crt'))
try {
    $skiExtension = $ca.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' }
    if (-not $skiExtension) { throw 'CA Subject Key Identifier missing' }
    $ski = New-Object Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($skiExtension, $skiExtension.Critical)
    $id = [byte[]]@(for ($i = 0; $i -lt $ski.SubjectKeyIdentifier.Length; $i += 2) {
        [Convert]::ToByte($ski.SubjectKeyIdentifier.Substring($i, 2), 16)
    })
    # Go emits AuthorityKeyIdentifier as a sequence with the [0] keyIdentifier.
    $expected = [BitConverter]::ToString([byte[]](@(0x30, ($id.Length + 2), 0x80, $id.Length) + $id))
    foreach ($stem in @('server', 'client')) {
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2((Join-Path $certDir "$stem.crt"))
        try {
            $aki = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.35' }
            if (-not $aki -or [BitConverter]::ToString($aki.RawData) -ne $expected) {
                throw "$stem certificate does not identify its CA"
            }
        } finally { $cert.Dispose() }
    }
} finally { $ca.Dispose() }
Write-Host 'PASS: Windows server and slave certificates identify the issued CA'
