param(
    [ValidateSet("install", "build", "configs", "certs")]
    [string]$Mode = "install",

    [ValidateSet("master", "slave", "both")]
    [string]$Config = "both",

    [switch]$SkipBuild,
    [switch]$SkipCerts,
    [switch]$Force,

    [string]$GoVersion = "1.25.0",

    [string]$SlaveName = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ToolsDir = Join-Path $Root ".tools"
Set-Location $Root

if ($SlaveName -and $SlaveName -notmatch '^[A-Za-z0-9._-]+$') {
    throw "SlaveName may contain only letters, numbers, dots, underscores, and dashes."
}

function Say($Message = "") {
    Write-Host $Message
}

function Assert-NativeSuccess([string]$Action) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed with exit code $LASTEXITCODE."
    }
}

function To-ConfigPath([string]$Path) {
    return ($Path -replace "\\", "/")
}

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Write-Utf8NoBom([string]$Path, [string]$Value) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Get-TextCorruptionScore([string]$Value) {
    $score = 0
    foreach ($character in $Value.ToCharArray()) {
        $codePoint = [int]$character
        if (($codePoint -lt 32 -and $codePoint -notin 9, 10, 13) -or
            ($codePoint -ge 127 -and $codePoint -le 159)) {
            $score += 100
        }
        if ($character -in @([char]0x00C2, [char]0x00C3, [char]0x00E2, [char]0x00F0, [char]0xFFFD)) {
            $score++
        }
    }
    return $score
}

function Read-Utf8Text([string]$Path) {
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $original = $utf8.GetString([System.IO.File]::ReadAllBytes($Path))
    $current = $original
    $currentScore = Get-TextCorruptionScore $current

    if ($currentScore -gt 0) {
        $codePage = [Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage
        $ansi = [System.Text.Encoding]::GetEncoding(
            $codePage,
            [System.Text.EncoderFallback]::ExceptionFallback,
            [System.Text.DecoderFallback]::ExceptionFallback
        )

        for ($pass = 0; $pass -lt 4; $pass++) {
            try {
                $candidate = $utf8.GetString($ansi.GetBytes($current))
            } catch {
                break
            }
            $candidateScore = Get-TextCorruptionScore $candidate
            if ($candidateScore -ge $currentScore) {
                break
            }
            $current = $candidate
            $currentScore = $candidateScore
        }
    }

    if ($current -ne $original) {
        Say "repair UTF-8 text in $Path"
        Write-Utf8NoBom $Path $current
    }
    return $current
}

function Get-GoArch {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
        return "arm64"
    }
    return "amd64"
}

function Get-GoVersion([string]$GoExe) {
    try {
        $versionOutput = (& $GoExe version 2>$null | Select-Object -First 1)
        if ($versionOutput -match '\bgo(\d+\.\d+(?:\.\d+)?)\b') {
            return [version]$Matches[1]
        }
    } catch {
        return $null
    }
    return $null
}

function Ensure-Go {
    $requiredVersion = [version]$GoVersion
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) {
        $installedVersion = Get-GoVersion $cmd.Source
        if ($installedVersion -and $installedVersion -ge $requiredVersion) {
            Say "found  Go $installedVersion`: $($cmd.Source)"
            return $cmd.Source
        }
        Say "skip   system Go $installedVersion (need Go $requiredVersion or newer)"
    }

    $goRoot = Join-Path $ToolsDir "go"
    $goExe = Join-Path $goRoot "bin/go.exe"
    if (Test-Path -LiteralPath $goExe) {
        $bundledVersion = Get-GoVersion $goExe
        if ($bundledVersion -and $bundledVersion -ge $requiredVersion) {
            $env:PATH = "$(Join-Path $goRoot "bin");$env:PATH"
            Say "found  bundled Go $bundledVersion`: $goExe"
            return $goExe
        }
        Say "replace bundled Go $bundledVersion (need Go $requiredVersion or newer)"
    }

    $arch = Get-GoArch
    $downloads = Join-Path $ToolsDir "downloads"
    Ensure-Dir $downloads
    $zip = Join-Path $downloads "go$GoVersion.windows-$arch.zip"
    $url = "https://go.dev/dl/go$GoVersion.windows-$arch.zip"

    Say "Go not found; downloading $url"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    if (Test-Path -LiteralPath $goRoot) {
        Remove-Item -LiteralPath $goRoot -Recurse -Force
    }
    Expand-Archive -LiteralPath $zip -DestinationPath $ToolsDir -Force
    if (-not (Test-Path -LiteralPath $goExe)) {
        throw "Downloaded Go archive did not create $goExe"
    }
    $env:PATH = "$(Join-Path $goRoot "bin");$env:PATH"
    Say "ready  bundled Go: $goExe"
    return $goExe
}

function Copy-IfMissing([string]$Source, [string]$Destination) {
    if ((Test-Path -LiteralPath $Destination) -and -not $Force) {
        Say "keep   $Destination"
        return $false
    }
    Ensure-Dir (Split-Path -Parent $Destination)
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    Say "write  $Destination"
    return $true
}

function Replace-Text([string]$Path, [string]$Old, [string]$New) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $text = Read-Utf8Text $Path
    if ($text.Contains($Old)) {
        $text = $text.Replace($Old, $New)
        Write-Utf8NoBom $Path $text
    }
}

function Replace-Regex([string]$Path, [string]$Pattern, [string]$Replacement) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $text = Read-Utf8Text $Path
    $updated = [regex]::Replace($text, $Pattern, $Replacement)
    if ($updated -ne $text) {
        Write-Utf8NoBom $Path $updated
    }
}

function Copy-PluginConfigs([string]$BaseDir) {
    if (-not (Test-Path -LiteralPath $BaseDir)) {
        return
    }
    Get-ChildItem -LiteralPath $BaseDir -Recurse -Filter "config.yml.dist" | ForEach-Object {
        $dest = Join-Path $_.DirectoryName "config.yml"
        if ((Test-Path -LiteralPath $dest) -and -not $Force) {
            Say "keep   $dest"
        } else {
            Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
            Say "write  $dest"
        }
    }
}

function Write-RunScripts {
    $master = @'
Set-Location $PSScriptRoot
.\weaveftpd.exe --config etc/config.yml
'@
    $slave = @'
Set-Location $PSScriptRoot
.\weaveftpd.exe --config etc/config-slave.yml
'@
    $sitebot = @'
Set-Location (Join-Path $PSScriptRoot "sitebot")
.\sitebot.exe --config etc/config.yml
'@
    Write-Utf8NoBom (Join-Path $Root "run-master.ps1") $master
    Write-Utf8NoBom (Join-Path $Root "run-slave.ps1") $slave
    Write-Utf8NoBom (Join-Path $Root "run-sitebot.ps1") $sitebot
    Say "write  run-master.ps1"
    Say "write  run-slave.ps1"
    Say "write  run-sitebot.ps1"
}

function Install-Configs {
    Say "Preparing directories and configs..."
    foreach ($dir in @("logs", "site", "userdata", "etc/certs", "sitebot/logs")) {
        Ensure-Dir (Join-Path $Root $dir)
    }

    $eventFile = Join-Path $Root "etc/weaveftpd.sitebot.events.log"
    if (-not (Test-Path -LiteralPath $eventFile)) {
        New-Item -ItemType File -Path $eventFile | Out-Null
        Say "write  $eventFile"
    } else {
        Say "keep   $eventFile"
    }

    if ($Config -eq "master" -or $Config -eq "both") {
        Copy-IfMissing (Join-Path $Root "etc/config-example.yml") (Join-Path $Root "etc/config.yml") | Out-Null
    }
    if ($Config -eq "slave" -or $Config -eq "both") {
        Copy-IfMissing (Join-Path $Root "etc/config-slave-example.yml") (Join-Path $Root "etc/config-slave.yml") | Out-Null
    }
    Copy-IfMissing (Join-Path $Root "sitebot/etc/config.yml.example") (Join-Path $Root "sitebot/etc/config.yml") | Out-Null

    $eventConfigPath = To-ConfigPath $eventFile
    $sitebotConfigPath = To-ConfigPath (Join-Path $Root "sitebot/etc/config.yml")
    foreach ($cfg in @((Join-Path $Root "etc/config.yml"), (Join-Path $Root "sitebot/etc/config.yml"))) {
        Replace-Text $cfg "/WeaveFTPd/etc/weaveftpd.sitebot.fifo" $eventConfigPath
        Replace-Text $cfg "/WeaveFTPd/etc/weaveftpd.sitebot.events.log" $eventConfigPath
    }
    Replace-Text (Join-Path $Root "etc/config.yml") "/WeaveFTPd/sitebot/etc/config.yml" $sitebotConfigPath

    Copy-PluginConfigs (Join-Path $Root "plugins")
    Copy-PluginConfigs (Join-Path $Root "sitebot/plugins")
    Write-RunScripts
}

function Build-Binaries {
    $goExe = Ensure-Go
    Say "Building weaveftpd.exe..."
    & $goExe build -o (Join-Path $Root "weaveftpd.exe") ./cmd/weaveftpd
    Assert-NativeSuccess "Daemon build"

    Say "Building sitebot.exe..."
    Push-Location (Join-Path $Root "sitebot")
    try {
        & $goExe build -o (Join-Path $Root "sitebot/sitebot.exe") ./cmd
        Assert-NativeSuccess "Sitebot build"
    } finally {
        Pop-Location
    }
}

function Resolve-SlaveName {
    if ($SlaveName) {
        return $SlaveName
    }

    $slaveConfig = Join-Path $Root "etc/config-slave.yml"
    if (Test-Path -LiteralPath $slaveConfig) {
        $text = Read-Utf8Text $slaveConfig
        $match = [regex]::Match($text, '(?m)^\s+name:\s*["'']?([A-Za-z0-9._-]+)["'']?\s*(?:#.*)?$')
        if ($match.Success) {
            return $match.Groups[1].Value
        }
    }

    return "LOCAL"
}

function Get-ClientCertificateName([string]$ClientCert) {
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ClientCert)
        try {
            return $cert.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
                $false
            )
        } finally {
            $cert.Dispose()
        }
    } catch {
        return $null
    }
}

function Configure-GeneratedMTLS([string]$Name) {
    $masterConfig = Join-Path $Root "etc/config.yml"
    $slaveConfig = Join-Path $Root "etc/config-slave.yml"

    Replace-Regex $masterConfig '(?m)^(\s*slave_ca_cert:\s*)""(\s*(?:#.*)?)$' '${1}"./etc/certs/ca.crt"${2}'

    if ($SlaveName -and (Test-Path -LiteralPath $slaveConfig)) {
        $nameReplacement = '${1}"' + $Name + '"${2}'
        Replace-Regex $slaveConfig '(?m)^(\s{2}name:\s*)(?:"[^"]*"|''[^'']*''|[^\s#]+)(\s*(?:#.*)?)$' $nameReplacement
    }
    Replace-Regex $slaveConfig '(?m)^(\s*master_ca_cert:\s*)""(\s*(?:#.*)?)$' '${1}"./etc/certs/ca.crt"${2}'
    Replace-Regex $slaveConfig '(?m)^(\s*client_cert:\s*)""(\s*(?:#.*)?)$' '${1}"./etc/certs/client.crt"${2}'
    Replace-Regex $slaveConfig '(?m)^(\s*client_key:\s*)""(\s*(?:#.*)?)$' '${1}"./etc/certs/client.key"${2}'
}

function Generate-CertsWithGo([string]$GoExe, [string]$CertDir, [string]$Name) {
    Ensure-Dir $ToolsDir
    $helper = Join-Path $ToolsDir "makecerts.go"
    $source = @'
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: makecerts <cert-dir> <slave-name>")
	}
	dir := os.Args[1]
	slaveName := os.Args[2]
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatal(err)
	}

	caKey := mustKey()
	serverKey := mustKey()
	clientKey := mustKey()

	now := time.Now().Add(-time.Hour)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "WeaveFTPd Root CA", Organization: []string{"WeaveFTPd"}},
		NotBefore: now,
		NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA: true,
	}
	server := leaf(2, "WeaveFTPd FTP", x509.ExtKeyUsageServerAuth)
	server.DNSNames = []string{"localhost"}
	server.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	client := leaf(3, slaveName, x509.ExtKeyUsageClientAuth)

	caDER := mustCert(ca, ca, &caKey.PublicKey, caKey)
	writeCert(filepath.Join(dir, "ca.crt"), caDER)
	// Reuse the issued CA, including its generated SubjectKeyId, for leaf signing.
	var err error
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}
	writeKey(filepath.Join(dir, "ca.key"), caKey)
	writeCert(filepath.Join(dir, "server.crt"), mustCert(server, ca, &serverKey.PublicKey, caKey))
	writeKey(filepath.Join(dir, "server.key"), serverKey)
	writeCert(filepath.Join(dir, "client.crt"), mustCert(client, ca, &clientKey.PublicKey, caKey))
	writeKey(filepath.Join(dir, "client.key"), clientKey)
}

func leaf(serial int64, cn string, usage x509.ExtKeyUsage) *x509.Certificate {
	now := time.Now().Add(-time.Hour)
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{CommonName: cn, Organization: []string{"WeaveFTPd"}},
		NotBefore: now,
		NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
}

func mustKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func mustCert(tmpl, parent *x509.Certificate, pub interface{}, parentKey interface{}) []byte {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		log.Fatal(err)
	}
	return der
}

func writeCert(path string, der []byte) {
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatal(err)
	}
}

func writeKey(path string, key *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Fatal(err)
	}
}
'@
    Write-Utf8NoBom $helper $source
    Say "Generating localhost TLS and mTLS certificates with Go."
    & $GoExe run $helper $CertDir $Name
    Assert-NativeSuccess "Certificate generation"
}

function Generate-Certs {
    $certDir = Join-Path $Root "etc/certs"
    $name = Resolve-SlaveName
    $requiredFiles = @("ca.crt", "ca.key", "server.crt", "server.key", "client.crt", "client.key")
    $missingFiles = @($requiredFiles | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $certDir $_))
    })

    if ($missingFiles.Count -eq 0 -and -not $Force) {
        $clientName = Get-ClientCertificateName (Join-Path $certDir "client.crt")
        if ($clientName -ne $name) {
            throw "Existing client.crt has CN '$clientName', but slave.name is '$name'. Run setup.ps1 -Mode certs -Force to regenerate the local certificate set."
        }
        Configure-GeneratedMTLS $name
        Say "keep   TLS certs in $certDir (slave identity: $name)"
        return
    }

    if ($missingFiles.Count -ne $requiredFiles.Count -and -not $Force) {
        throw "TLS certificate set is incomplete (missing: $($missingFiles -join ', ')). Run setup.ps1 -Mode certs -Force to regenerate it."
    }

    $goExe = Ensure-Go
    Ensure-Dir $certDir
    Generate-CertsWithGo $goExe $certDir $name
    Configure-GeneratedMTLS $name
    Say "ready  TLS certs in $certDir (slave identity: $name)"
}

Say "=============================================================="
Say "WeaveFTPd Windows console setup"
Say "=============================================================="

switch ($Mode) {
    "configs" {
        Install-Configs
    }
    "certs" {
        Generate-Certs
    }
    "build" {
        Build-Binaries
    }
    "install" {
        Install-Configs
        if (-not $SkipCerts) {
            Generate-Certs
        }
        if (-not $SkipBuild) {
            Build-Binaries
        }
    }
}

Say ""
Say "Console start commands:"
Say "  .\run-master.ps1"
Say "  .\run-slave.ps1"
Say "  .\run-sitebot.ps1"
Say ""
Say "Windows event note:"
Say "  event_fifo points at a regular append-only event file on Windows."
Say "  The daemon appends JSON lines; the sitebot tails only new lines."
Say ""
Say "Dependency note:"
Say "  If go.exe is missing, setup downloads Go $GoVersion into .tools\go."
Say "  OpenSSL is not required; setup generates certificates with Go."
