param(
    [string]$OutDir = "",
    [string]$CodeSigningCertificateThumbprint = "",
    [string]$CodeSigningCertificatePath = "",
    [string]$CodeSigningCertificatePassword = "",
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [switch]$RequireCodeSigning,
    [switch]$AllowUnsignedDevelopmentPackage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Version = (Get-Content (Join-Path $Root "VERSION") -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Root "dist\release-$Version"
} elseif (-not [System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $Root $OutDir
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
$RuntimeManifest = Join-Path $Root "runtime\neverruntime\Cargo.toml"
$DesktopManifest = Join-Path $Root "apps\desktop\src-tauri\Cargo.toml"

if ([string]::IsNullOrWhiteSpace($CodeSigningCertificateThumbprint)) {
    $CodeSigningCertificateThumbprint = [Environment]::GetEnvironmentVariable("NEVERLAUNCHER_WINDOWS_SIGNING_CERT_THUMBPRINT")
}
if ([string]::IsNullOrWhiteSpace($CodeSigningCertificatePath)) {
    $CodeSigningCertificatePath = [Environment]::GetEnvironmentVariable("NEVERLAUNCHER_WINDOWS_SIGNING_PFX_FILE")
}
if ([string]::IsNullOrWhiteSpace($CodeSigningCertificatePassword)) {
    $CodeSigningCertificatePassword = [Environment]::GetEnvironmentVariable("NEVERLAUNCHER_WINDOWS_SIGNING_PFX_PASSWORD")
}
$TimestampFromEnv = [Environment]::GetEnvironmentVariable("NEVERLAUNCHER_WINDOWS_TIMESTAMP_URL")
if (-not [string]::IsNullOrWhiteSpace($TimestampFromEnv)) {
    $TimestampServer = $TimestampFromEnv
}

function Invoke-Checked([scriptblock]$Command, [string]$Label) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Write-JsonNoBom([string]$Path, $Value, [int]$Depth = 12) {
    $Json = $Value | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText($Path, $Json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

function Get-SignToolPath {
    $Command = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $Command) { return $Command.Source }
    $KitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path $KitsRoot) {
        $Candidates = @(Get-ChildItem $KitsRoot -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending)
        if ($Candidates.Count -gt 0) { return $Candidates[0].FullName }
    }
    throw "signtool.exe was not found. Install Windows 10/11 SDK signing tools."
}

function Find-CodeSigningCertificate([string]$Thumbprint) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
    $Normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    foreach ($Entry in @(
        @{ Store = "Cert:\CurrentUser\My"; Scope = "CurrentUser" },
        @{ Store = "Cert:\LocalMachine\My"; Scope = "LocalMachine" }
    )) {
        $Candidate = Get-ChildItem $Entry.Store -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint.Replace(" ", "").ToUpperInvariant() -eq $Normalized } |
            Select-Object -First 1
        if ($null -ne $Candidate) {
            return [pscustomobject]@{ Certificate = $Candidate; StoreScope = $Entry.Scope; Imported = $false }
        }
    }
    throw "Code-signing certificate not found for thumbprint $Thumbprint"
}

function Import-CodeSigningCertificate([string]$Path, [string]$Password) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $Resolved = (Resolve-Path $Path).Path
    $SecurePassword = if ([string]::IsNullOrEmpty($Password)) {
        New-Object System.Security.SecureString
    } else {
        ConvertTo-SecureString -String $Password -AsPlainText -Force
    }
    $Certificate = Import-PfxCertificate -FilePath $Resolved -CertStoreLocation "Cert:\CurrentUser\My" -Password $SecurePassword -Exportable:$false
    if ($null -eq $Certificate) { throw "PFX import did not return a certificate" }
    $Certificate = $Certificate | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    if ($null -eq $Certificate) { throw "Imported PFX does not contain a private code-signing key" }
    return [pscustomobject]@{ Certificate = $Certificate; StoreScope = "CurrentUser"; Imported = $true }
}

function Resolve-CodeSigningCertificate {
    $Resolved = $null
    if (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificatePath)) {
        $Resolved = Import-CodeSigningCertificate $CodeSigningCertificatePath $CodeSigningCertificatePassword
        if (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificateThumbprint) -and
            $Resolved.Certificate.Thumbprint.Replace(" ", "").ToUpperInvariant() -ne $CodeSigningCertificateThumbprint.Replace(" ", "").ToUpperInvariant()) {
            throw "Imported PFX thumbprint does not match requested certificate thumbprint"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificateThumbprint)) {
        $Resolved = Find-CodeSigningCertificate $CodeSigningCertificateThumbprint
    }
    if ($null -eq $Resolved) { return $null }
    $Certificate = $Resolved.Certificate
    if (-not $Certificate.HasPrivateKey) { throw "Code-signing certificate has no private key" }
    $CodeSigningEku = $Certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId.Value -eq "1.3.6.1.5.5.7.3.3" } | Select-Object -First 1
    if ($null -eq $CodeSigningEku) { throw "Certificate is missing Code Signing EKU 1.3.6.1.5.5.7.3.3" }
    $Now = Get-Date
    if ($Now -lt $Certificate.NotBefore -or $Now -gt $Certificate.NotAfter) { throw "Code-signing certificate is outside its validity interval" }
    return $Resolved
}

function Get-PEMachine([string]$Path) {
    $Stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $Reader = New-Object System.IO.BinaryReader($Stream)
        if ($Reader.ReadUInt16() -ne 0x5A4D) { throw "$Path is not an MZ executable" }
        $Stream.Position = 0x3C
        $PeOffset = $Reader.ReadUInt32()
        if ($PeOffset -lt 0x40 -or $PeOffset -gt ($Stream.Length - 24)) { throw "$Path has invalid PE offset" }
        $Stream.Position = $PeOffset
        if ($Reader.ReadUInt32() -ne 0x00004550) { throw "$Path has invalid PE signature" }
        return $Reader.ReadUInt16()
    } finally {
        $Stream.Dispose()
    }
}

function Assert-PEArchitecture([string]$Path, [int]$ExpectedMachine, [string]$Architecture) {
    $Actual = Get-PEMachine $Path
    if ($Actual -ne $ExpectedMachine) {
        throw "$Path PE machine mismatch for $Architecture: expected 0x$('{0:X4}' -f $ExpectedMachine), got 0x$('{0:X4}' -f $Actual)"
    }
}

function Invoke-SignTool([string]$SignTool, [string[]]$Arguments, [string]$Label) {
    & $SignTool @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE" }
}

function Sign-And-VerifyAuthenticode([string]$Path, $SigningContext, [string]$SignTool) {
    $Thumbprint = $SigningContext.Certificate.Thumbprint.Replace(" ", "")
    $SignArgs = @("sign", "/sha1", $Thumbprint, "/fd", "SHA256", "/tr", $TimestampServer, "/td", "SHA256", "/v")
    if ($SigningContext.StoreScope -eq "LocalMachine") { $SignArgs += "/sm" }
    $SignArgs += $Path
    Invoke-SignTool $SignTool $SignArgs "signtool sign $Path"
    Invoke-SignTool $SignTool @("verify", "/pa", "/all", "/v", $Path) "signtool verify $Path"

    $Signature = Get-AuthenticodeSignature -FilePath $Path
    if ($Signature.Status -ne "Valid") {
        throw "Authenticode verification failed for $Path: $($Signature.Status) $($Signature.StatusMessage)"
    }
    if ($null -eq $Signature.SignerCertificate -or $Signature.SignerCertificate.Thumbprint -ne $SigningContext.Certificate.Thumbprint) {
        throw "Authenticode signer mismatch for $Path"
    }
    if ($null -eq $Signature.TimeStamperCertificate) {
        throw "RFC3161 timestamp is missing for $Path"
    }
    return $Signature
}

function Get-ArtifactRecord([string]$Path, [string]$Name, [string]$Component, [string]$Architecture, [string]$PEMachine, $Signature, [bool]$Signed) {
    $Item = Get-Item $Path
    $Hash = (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLowerInvariant()
    $Record = [ordered]@{
        name = $Name
        component = $Component
        architecture = $Architecture
        peMachine = $PEMachine
        size = $Item.Length
        sha256 = $Hash
        authenticodeStatus = $(if ($Signed) { "Valid" } else { "NotSigned" })
        timestamped = $Signed
        signtoolVerified = $Signed
    }
    if ($Signed) {
        $Record["signerThumbprint"] = $Signature.SignerCertificate.Thumbprint.ToLowerInvariant()
        $Record["timestampSignerThumbprint"] = $Signature.TimeStamperCertificate.Thumbprint.ToLowerInvariant()
    }
    return $Record
}

$Targets = @(
    [pscustomobject]@{ Architecture = "x64"; GoArch = "amd64"; RustTarget = "x86_64-pc-windows-msvc"; Machine = 0x8664; MachineText = "0x8664" },
    [pscustomobject]@{ Architecture = "arm64"; GoArch = "arm64"; RustTarget = "aarch64-pc-windows-msvc"; Machine = 0xAA64; MachineText = "0xAA64" }
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$SigningContext = $null
$SignTool = $null
try {
    $SigningContext = Resolve-CodeSigningCertificate
    $SignedProduction = $null -ne $SigningContext
    $SigningRequired = $RequireCodeSigning -or (-not $AllowUnsignedDevelopmentPackage)
    if ($SigningRequired -and -not $SignedProduction) {
        throw "Production Windows x64+ARM64 delivery requires Authenticode credentials. Pass -CodeSigningCertificateThumbprint or -CodeSigningCertificatePath. Use -AllowUnsignedDevelopmentPackage only for CI/development candidates."
    }
    if ($SignedProduction) {
        if ([string]::IsNullOrWhiteSpace($TimestampServer)) { throw "Production Authenticode signing requires an RFC3161 timestamp server" }
        $SignTool = Get-SignToolPath
    }

    Push-Location (Join-Path $Root "apps\desktop")
    try {
        Invoke-Checked { npm.cmd ci } "Desktop npm ci"
        Invoke-Checked { npm.cmd run build } "Desktop frontend build"
    } finally {
        Pop-Location
    }

    $EvidenceTargets = @()
    $GuardPairs = @()
    foreach ($Target in $Targets) {
        $Arch = $Target.Architecture
        $PackageDir = Join-Path $OutDir "windows-$Arch-package"
        if (Test-Path $PackageDir) { Remove-Item -Recurse -Force $PackageDir }
        New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null

        Invoke-Checked { rustup target add $Target.RustTarget } "rustup target add $($Target.RustTarget)"
        Invoke-Checked { cargo build --release --target $Target.RustTarget --manifest-path $RuntimeManifest --bin neverguard } "NeverGuard $Arch release build"
        Invoke-Checked { cargo build --release --target $Target.RustTarget --manifest-path $DesktopManifest } "Desktop $Arch native release build"

        $DesktopSource = Join-Path $Root "apps\desktop\src-tauri\target\$($Target.RustTarget)\release\neverlauncher-desktop.exe"
        $GuardSource = Join-Path $Root "runtime\neverruntime\target\$($Target.RustTarget)\release\neverguard.exe"
        if (-not (Test-Path $DesktopSource -PathType Leaf)) { throw "Desktop $Arch artifact missing: $DesktopSource" }
        if (-not (Test-Path $GuardSource -PathType Leaf)) { throw "NeverGuard $Arch artifact missing: $GuardSource" }

        $DesktopPackageName = "neverlauncher-desktop-$Version-windows-$Arch.exe"
        $DesktopPackagePath = Join-Path $PackageDir $DesktopPackageName
        $GuardPackagePath = Join-Path $PackageDir "neverguard.exe"
        Copy-Item $DesktopSource $DesktopPackagePath -Force
        Copy-Item $GuardSource $GuardPackagePath -Force

        $CliRootName = "neverlauncher-cli-windows-$Arch.exe"
        $CliRootPath = Join-Path $OutDir $CliRootName
        Push-Location (Join-Path $Root "cli")
        $OldGOOS = $env:GOOS; $OldGOARCH = $env:GOARCH; $OldCGO = $env:CGO_ENABLED
        try {
            $env:GOOS = "windows"; $env:GOARCH = $Target.GoArch; $env:CGO_ENABLED = "0"
            Invoke-Checked { go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $CliRootPath .\cmd\neverlauncher } "CLI $Arch release build"
        } finally {
            $env:GOOS = $OldGOOS; $env:GOARCH = $OldGOARCH; $env:CGO_ENABLED = $OldCGO
            Pop-Location
        }

        Assert-PEArchitecture $DesktopPackagePath $Target.Machine $Arch
        Assert-PEArchitecture $GuardPackagePath $Target.Machine $Arch
        Assert-PEArchitecture $CliRootPath $Target.Machine $Arch

        $DesktopSignature = $null; $GuardSignature = $null; $CliSignature = $null
        if ($SignedProduction) {
            $DesktopSignature = Sign-And-VerifyAuthenticode $DesktopPackagePath $SigningContext $SignTool
            $GuardSignature = Sign-And-VerifyAuthenticode $GuardPackagePath $SigningContext $SignTool
            $CliSignature = Sign-And-VerifyAuthenticode $CliRootPath $SigningContext $SignTool
            Assert-PEArchitecture $DesktopPackagePath $Target.Machine $Arch
            Assert-PEArchitecture $GuardPackagePath $Target.Machine $Arch
            Assert-PEArchitecture $CliRootPath $Target.Machine $Arch
        }

        $DesktopRecord = Get-ArtifactRecord $DesktopPackagePath $DesktopPackageName "desktop-launcher" $Arch $Target.MachineText $DesktopSignature $SignedProduction
        $GuardRecord = Get-ArtifactRecord $GuardPackagePath "neverguard.exe" "guard" $Arch $Target.MachineText $GuardSignature $SignedProduction
        $Manifest = [ordered]@{
            schemaVersion = "1.1"
            productVersion = $Version
            platform = "windows-$Arch"
            architecture = $Arch
            rustTarget = $Target.RustTarget
            peMachine = $Target.MachineText
            neverGuardProtocolVersion = 4
            processBoundary = "separate-neverguard-executable"
            authenticatedIpc = "windows-named-pipe+current-user-system-acl+hmac-sha256-v4"
            windowsProductionHardeningVersion = 1
            securePipeAcl = "LocalSystem+current-user"
            launcherLifetimeBoundary = "job-object-kill-on-close"
            packageVerification = "sha256+pe-machine+authenticode-before-neverguard-spawn"
            authenticodeRequired = $SignedProduction
            signingMode = $(if ($SignedProduction) { "authenticode-rfc3161" } else { "unsigned-development" })
            signerThumbprint = $(if ($SignedProduction) { $SigningContext.Certificate.Thumbprint.ToLowerInvariant() } else { "" })
            timestampServer = $(if ($SignedProduction) { $TimestampServer } else { "" })
            requiredAdjacentArtifacts = @("neverguard.exe")
            artifacts = @($DesktopRecord, $GuardRecord)
        }
        $PackageManifestPath = Join-Path $PackageDir "WINDOWS_PACKAGE_MANIFEST.json"
        Write-JsonNoBom $PackageManifestPath $Manifest
        $RootManifestName = "WINDOWS_PACKAGE_MANIFEST_$($Arch.ToUpperInvariant()).json"
        $RootManifestPath = Join-Path $OutDir $RootManifestName
        Copy-Item $PackageManifestPath $RootManifestPath -Force

        $ZipName = "neverlauncher-desktop-$Version-windows-$Arch.zip"
        $ZipPath = Join-Path $OutDir $ZipName
        if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
        Compress-Archive -Path (Join-Path $PackageDir "*") -DestinationPath $ZipPath -CompressionLevel Optimal
        if (-not (Test-Path $ZipPath -PathType Leaf)) { throw "Windows $Arch package was not created: $ZipPath" }

        $DesktopRootName = "neverlauncher-desktop-windows-$Arch.exe"
        $GuardRootName = "neverguard-windows-$Arch.exe"
        $DesktopRootPath = Join-Path $OutDir $DesktopRootName
        $GuardRootPath = Join-Path $OutDir $GuardRootName
        Copy-Item $DesktopPackagePath $DesktopRootPath -Force
        Copy-Item $GuardPackagePath $GuardRootPath -Force

        $DesktopRootSignature = if ($SignedProduction) { Get-AuthenticodeSignature $DesktopRootPath } else { $null }
        $GuardRootSignature = if ($SignedProduction) { Get-AuthenticodeSignature $GuardRootPath } else { $null }
        $CliRootSignature = if ($SignedProduction) { Get-AuthenticodeSignature $CliRootPath } else { $null }
        $EvidenceArtifacts = @(
            (Get-ArtifactRecord $CliRootPath $CliRootName "cli" $Arch $Target.MachineText $CliRootSignature $SignedProduction),
            (Get-ArtifactRecord $DesktopRootPath $DesktopRootName "desktop-launcher" $Arch $Target.MachineText $DesktopRootSignature $SignedProduction),
            (Get-ArtifactRecord $GuardRootPath $GuardRootName "guard" $Arch $Target.MachineText $GuardRootSignature $SignedProduction)
        )
        $ZipItem = Get-Item $ZipPath
        $ManifestHash = (Get-FileHash -Algorithm SHA256 $RootManifestPath).Hash.ToLowerInvariant()
        $EvidenceTargets += [ordered]@{
            architecture = $Arch
            rustTarget = $Target.RustTarget
            peMachine = $Target.MachineText
            package = [ordered]@{
                name = $ZipName
                size = $ZipItem.Length
                sha256 = (Get-FileHash -Algorithm SHA256 $ZipPath).Hash.ToLowerInvariant()
                manifest = $RootManifestName
                manifestSha256 = $ManifestHash
            }
            artifacts = $EvidenceArtifacts
        }
        $GuardPairs += [ordered]@{
            guardSha256 = (Get-FileHash -Algorithm SHA256 $GuardRootPath).Hash.ToLowerInvariant()
            launcherSha256 = (Get-FileHash -Algorithm SHA256 $DesktopRootPath).Hash.ToLowerInvariant()
            requireAuthenticode = $SignedProduction
        }
    }

    $GuardReleaseAllowlist = [ordered]@{
        schemaVersion = "2.0"
        releases = [ordered]@{
            $Version = [ordered]@{
                protocolVersion = 4
                platforms = [ordered]@{
                    windows = [ordered]@{
                        signingMode = $(if ($SignedProduction) { "authenticode" } else { "unsigned-development" })
                        artifacts = $GuardPairs
                    }
                }
            }
        }
    }
    Write-JsonNoBom (Join-Path $OutDir "GUARD_RELEASE_ALLOWLIST_WINDOWS.json") $GuardReleaseAllowlist
    Write-JsonNoBom (Join-Path $OutDir "GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json") $GuardReleaseAllowlist

    # Backward-compatible x64 Guard CI package. This is a distinct certification
    # artifact using the historical schema/platform contract; it is deliberately
    # excluded from DELIVERY_MANIFEST.json for 0.15.2+.
    $LegacyDesktopRoot = Join-Path $OutDir "neverlauncher-desktop-windows-amd64.exe"
    $LegacyGuardRoot = Join-Path $OutDir "neverguard-windows-amd64.exe"
    $LegacyCliRoot = Join-Path $OutDir "neverlauncher-cli-windows-amd64.exe"
    Copy-Item (Join-Path $OutDir "neverlauncher-desktop-windows-x64.exe") $LegacyDesktopRoot -Force
    Copy-Item (Join-Path $OutDir "neverguard-windows-x64.exe") $LegacyGuardRoot -Force
    Copy-Item (Join-Path $OutDir "neverlauncher-cli-windows-x64.exe") $LegacyCliRoot -Force

    $LegacyPackageDir = Join-Path $OutDir "windows-amd64-guard-ci-package"
    if (Test-Path $LegacyPackageDir) { Remove-Item -Recurse -Force $LegacyPackageDir }
    New-Item -ItemType Directory -Force -Path $LegacyPackageDir | Out-Null
    $LegacyDesktopName = "neverlauncher-desktop-$Version-windows-amd64.exe"
    $LegacyDesktopPackage = Join-Path $LegacyPackageDir $LegacyDesktopName
    $LegacyGuardPackage = Join-Path $LegacyPackageDir "neverguard.exe"
    Copy-Item $LegacyDesktopRoot $LegacyDesktopPackage -Force
    Copy-Item $LegacyGuardRoot $LegacyGuardPackage -Force
    $LegacyDesktopItem = Get-Item $LegacyDesktopPackage
    $LegacyGuardItem = Get-Item $LegacyGuardPackage
    $LegacyDesktopHash = (Get-FileHash -Algorithm SHA256 $LegacyDesktopPackage).Hash.ToLowerInvariant()
    $LegacyGuardHash = (Get-FileHash -Algorithm SHA256 $LegacyGuardPackage).Hash.ToLowerInvariant()
    $LegacyManifest = [ordered]@{
        schemaVersion = "1.0"
        productVersion = $Version
        platform = "windows-amd64"
        neverGuardProtocolVersion = 4
        processBoundary = "separate-neverguard-executable"
        authenticatedIpc = "windows-named-pipe+current-user-system-acl+hmac-sha256-v4"
        windowsProductionHardeningVersion = 1
        securePipeAcl = "LocalSystem+current-user"
        launcherLifetimeBoundary = "job-object-kill-on-close"
        packageVerification = "sha256+pe-machine+authenticode-before-neverguard-spawn"
        authenticodeRequired = $SignedProduction
        requiredAdjacentArtifacts = @("neverguard.exe")
        artifacts = @(
            [ordered]@{ name = $LegacyDesktopName; size = $LegacyDesktopItem.Length; sha256 = $LegacyDesktopHash },
            [ordered]@{ name = "neverguard.exe"; size = $LegacyGuardItem.Length; sha256 = $LegacyGuardHash }
        )
    }
    Write-JsonNoBom (Join-Path $LegacyPackageDir "WINDOWS_PACKAGE_MANIFEST.json") $LegacyManifest
    Copy-Item (Join-Path $OutDir "GUARD_RELEASE_ALLOWLIST_WINDOWS.json") (Join-Path $LegacyPackageDir "GUARD_RELEASE_ALLOWLIST.json") -Force
    Write-JsonNoBom (Join-Path $OutDir "WINDOWS_PACKAGE_MANIFEST.json") $LegacyManifest
    $LegacyZipPath = Join-Path $OutDir "neverlauncher-desktop-$Version-windows-amd64.zip"
    if (Test-Path $LegacyZipPath) { Remove-Item -Force $LegacyZipPath }
    Compress-Archive -Path (Join-Path $LegacyPackageDir "*") -DestinationPath $LegacyZipPath -CompressionLevel Optimal
    if (-not (Test-Path $LegacyZipPath -PathType Leaf)) { throw "Legacy Guard CI Windows package was not created: $LegacyZipPath" }

    $SignerEvidence = $null
    if ($SignedProduction) {
        $Certificate = $SigningContext.Certificate
        $SignerEvidence = [ordered]@{
            subject = $Certificate.Subject
            issuer = $Certificate.Issuer
            thumbprint = $Certificate.Thumbprint.ToLowerInvariant()
            serialNumber = $Certificate.SerialNumber.ToLowerInvariant()
            notBefore = $Certificate.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            notAfter = $Certificate.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    }
    $Evidence = [ordered]@{
        schemaVersion = "1.0"
        product = "NeverLauncher"
        productVersion = $Version
        platform = "windows"
        signingMode = $(if ($SignedProduction) { "authenticode-rfc3161" } else { "unsigned-development" })
        timestampServer = $(if ($SignedProduction) { $TimestampServer } else { "" })
        generatedAt = (Get-Date).ToUniversalTime().ToString("o")
        targets = $EvidenceTargets
    }
    if ($null -ne $SignerEvidence) { $Evidence["signer"] = $SignerEvidence }
    Write-JsonNoBom (Join-Path $OutDir "WINDOWS_SIGNING_EVIDENCE.json") $Evidence

    Write-Host "NeverLauncher $Version Windows x64+ARM64 packages prepared (signingMode=$($Evidence.signingMode))"
} finally {
    if ($null -ne $SigningContext -and $SigningContext.Imported) {
        $ImportedPath = "Cert:\CurrentUser\My\$($SigningContext.Certificate.Thumbprint)"
        if (Test-Path $ImportedPath) { Remove-Item $ImportedPath -Force -ErrorAction SilentlyContinue }
    }
}
