param(
    [string]$OutDir = ""
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

Copy-Item $DesktopSource (Join-Path $PackageDir $DesktopArtifact)
Copy-Item $GuardSource (Join-Path $PackageDir $GuardArtifact)

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
    neverGuardProtocolVersion = 3
    processBoundary = "separate-neverguard-executable"
    authenticatedIpc = "windows-named-pipe+hmac-sha256-v3"
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
    requireAuthenticode = $false
}
$GuardReleaseAllowlist | ConvertTo-Json -Depth 8 -Compress | Set-Content -Encoding UTF8 (Join-Path $PackageDir "GUARD_RELEASE_ALLOWLIST.json")

$ZipPath = Join-Path $OutDir $ZipArtifact
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path (Join-Path $PackageDir "*") -DestinationPath $ZipPath -CompressionLevel Optimal
if (-not (Test-Path $ZipPath -PathType Leaf)) { throw "Windows package was not created: $ZipPath" }

Write-Host "NeverLauncher $Version Windows package: $ZipPath"
