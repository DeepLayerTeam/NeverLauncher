param(
    [string]$OutDir = "",
    [string]$CodeSigningCertificateThumbprint = "",
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
$PackageDir = Join-Path $OutDir "windows-desktop-package"
$DesktopArtifact = "neverlauncher-desktop-$Version-windows-amd64.exe"
$GuardArtifact = "neverguard.exe"
$ZipArtifact = "neverlauncher-desktop-$Version-windows-amd64.zip"
$RuntimeManifest = Join-Path $Root "runtime\neverruntime\Cargo.toml"
$DesktopManifest = Join-Path $Root "apps\desktop\src-tauri\Cargo.toml"

function Invoke-Checked([scriptblock]$Command, [string]$Label) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Get-CodeSigningCertificate([string]$Thumbprint) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
    $Normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    foreach ($Store in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
        $Candidate = Get-ChildItem $Store -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint.Replace(" ", "").ToUpperInvariant() -eq $Normalized } |
            Select-Object -First 1
        if ($null -ne $Candidate) { return $Candidate }
    }
    throw "Code-signing certificate not found for thumbprint $Thumbprint"
}

function Set-And-VerifyAuthenticode([string]$Path, $Certificate) {
    $Params = @{ FilePath = $Path; Certificate = $Certificate; HashAlgorithm = "SHA256" }
    if (-not [string]::IsNullOrWhiteSpace($TimestampServer)) { $Params.TimestampServer = $TimestampServer }
    $Signed = Set-AuthenticodeSignature @Params
    if ($Signed.Status -ne "Valid") {
        throw "Authenticode signing failed for $Path: $($Signed.Status) $($Signed.StatusMessage)"
    }
    $Verified = Get-AuthenticodeSignature -FilePath $Path
    if ($Verified.Status -ne "Valid") {
        throw "Authenticode verification failed for $Path: $($Verified.Status) $($Verified.StatusMessage)"
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (Test-Path $PackageDir) {
    Remove-Item -Recurse -Force $PackageDir
}
New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null

Push-Location (Join-Path $Root "apps\desktop")
try {
    Invoke-Checked { npm.cmd ci } "Desktop npm ci"
    Invoke-Checked { npm.cmd run build } "Desktop frontend build"
} finally {
    Pop-Location
}

Invoke-Checked {
    cargo build --release --manifest-path $RuntimeManifest --bin neverguard
} "NeverGuard release build"
Invoke-Checked {
    cargo build --release --manifest-path $DesktopManifest
} "Desktop native release build"

$DesktopSource = Join-Path $Root "apps\desktop\src-tauri\target\release\neverlauncher-desktop.exe"
$GuardSource = Join-Path $Root "runtime\neverruntime\target\release\neverguard.exe"
if (-not (Test-Path $DesktopSource -PathType Leaf)) { throw "Desktop artifact missing: $DesktopSource" }
if (-not (Test-Path $GuardSource -PathType Leaf)) { throw "NeverGuard artifact missing: $GuardSource" }

$DesktopPath = Join-Path $PackageDir $DesktopArtifact
$GuardPath = Join-Path $PackageDir $GuardArtifact
Copy-Item $DesktopSource $DesktopPath
Copy-Item $GuardSource $GuardPath

$SigningCertificate = Get-CodeSigningCertificate $CodeSigningCertificateThumbprint
$AuthenticodeRequired = $null -ne $SigningCertificate
$SigningRequired = $RequireCodeSigning -or (-not $AllowUnsignedDevelopmentPackage)
if ($SigningRequired -and -not $AuthenticodeRequired) {
    throw "Production Windows package requires Authenticode signing. Pass -CodeSigningCertificateThumbprint. Use -AllowUnsignedDevelopmentPackage only for CI/development artifacts."
}
if ($AuthenticodeRequired) {
    Set-And-VerifyAuthenticode $DesktopPath $SigningCertificate
    Set-And-VerifyAuthenticode $GuardPath $SigningCertificate
}

$Artifacts = @($DesktopArtifact, $GuardArtifact) | ForEach-Object {
    $Path = Join-Path $PackageDir $_
    $Item = Get-Item $Path
    $Hash = (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLowerInvariant()
    [ordered]@{
        name = $_
        size = $Item.Length
        sha256 = $Hash
    }
}
$Manifest = [ordered]@{
    schemaVersion = "1.0"
    productVersion = $Version
    platform = "windows-amd64"
    neverGuardProtocolVersion = 4
    processBoundary = "separate-neverguard-executable"
    authenticatedIpc = "windows-named-pipe+current-user-system-acl+hmac-sha256-v4"
    windowsProductionHardeningVersion = 1
    securePipeAcl = "LocalSystem+current-user"
    launcherLifetimeBoundary = "job-object-kill-on-close"
    packageVerification = "sha256-before-neverguard-spawn"
    authenticodeRequired = $AuthenticodeRequired
    requiredAdjacentArtifacts = @($GuardArtifact)
    artifacts = $Artifacts
}
$Manifest | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $PackageDir "WINDOWS_PACKAGE_MANIFEST.json")

$DesktopHash = ($Artifacts | Where-Object { $_.name -eq $DesktopArtifact }).sha256
$GuardHash = ($Artifacts | Where-Object { $_.name -eq $GuardArtifact }).sha256
$GuardReleaseAllowlist = [ordered]@{}
$GuardReleaseAllowlist[$Version] = [ordered]@{
    guardSha256 = @($GuardHash)
    launcherSha256 = @($DesktopHash)
    requireAuthenticode = $AuthenticodeRequired
}
$GuardReleaseAllowlist | ConvertTo-Json -Depth 8 -Compress | Set-Content -Encoding UTF8 (Join-Path $PackageDir "GUARD_RELEASE_ALLOWLIST.json")

# Canonical cross-platform certification artifacts. These names are stable across
# patch versions and are hashed into the Guard CI matrix.
Copy-Item $DesktopPath (Join-Path $OutDir "neverlauncher-desktop-windows-amd64.exe") -Force
Copy-Item $GuardPath (Join-Path $OutDir "neverguard-windows-amd64.exe") -Force
Copy-Item (Join-Path $PackageDir "WINDOWS_PACKAGE_MANIFEST.json") (Join-Path $OutDir "WINDOWS_PACKAGE_MANIFEST.json") -Force
Copy-Item (Join-Path $PackageDir "GUARD_RELEASE_ALLOWLIST.json") (Join-Path $OutDir "GUARD_RELEASE_ALLOWLIST_WINDOWS.json") -Force

$ZipPath = Join-Path $OutDir $ZipArtifact
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path (Join-Path $PackageDir "*") -DestinationPath $ZipPath -CompressionLevel Optimal
if (-not (Test-Path $ZipPath -PathType Leaf)) { throw "Windows package was not created: $ZipPath" }

Write-Host "NeverLauncher $Version Windows package: $ZipPath"
