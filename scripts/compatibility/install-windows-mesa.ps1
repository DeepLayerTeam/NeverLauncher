# GitHub-hosted Windows runners have no modern OpenGL ICD. Install a known,
# SHA-256 pinned Mesa llvmpipe WGL runtime *only* in the disposable runner JDK.
# Source: https://github.com/mmozeiko/build-mesa/releases/tag/26.2.4
# Never use this as a production launcher or anti-cheat bypass.
param(
    [Parameter(Mandatory = $true)][ValidateSet('x86_64','aarch64')][string]$Architecture,
    [Parameter(Mandatory = $true)][string]$JavaExecutable
)
$ErrorActionPreference = 'Stop'
$mesaVersion = '26.2.4'
$arch = if ($Architecture -eq 'x86_64') { 'x64' } else { 'arm64' }
$hashes = @{
    'x64' = '6eff97dc5b33c8017a67eb617a1b010341b1569863caa8638b508983645daeec'
    'arm64' = '171e0cc3d48a2d435f7ebda28159d800bed7c4b2bda3ac7f9cc708b56f5499a1'
}
$peMachine = if ($arch -eq 'x64') { 0x8664 } else { 0xAA64 }
$javaPath = (Resolve-Path -LiteralPath $JavaExecutable).Path
if ([IO.Path]::GetFileName($javaPath) -ine 'java.exe') { throw 'Expected a pinned JDK java.exe' }
$runtimeDirectory = Split-Path -Parent $javaPath
$name = "mesa-llvmpipe-$arch-$mesaVersion.7z"
$url = "https://github.com/mmozeiko/build-mesa/releases/download/$mesaVersion/$name"
$work = Join-Path $env:RUNNER_TEMP ("neverlauncher-mesa-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $archive = Join-Path $work $name
    # Retry transient upstream failures but never accept changed bytes.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try { Invoke-WebRequest -Uri $url -OutFile $archive -MaximumRedirection 5; break }
        catch { if ($attempt -eq 3) { throw }; Start-Sleep -Seconds (2 * $attempt) }
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -cne $hashes[$arch]) { throw "Mesa archive checksum mismatch for $arch: $actual" }
    $sevenZip = Get-Command '7z.exe' -ErrorAction SilentlyContinue
    if (-not $sevenZip) { throw '7z.exe missing on Windows GitHub runner' }
    $unpack = Join-Path $work 'unpack'
    New-Item -ItemType Directory -Force -Path $unpack | Out-Null
    & $sevenZip.Source x '-y' "-o$unpack" $archive | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z extraction failed: $LASTEXITCODE" }
    $candidates = @(Get-ChildItem -Path $unpack -File -Recurse -Filter opengl32.dll)
    if ($candidates.Count -ne 1) { throw "Mesa package must contain exactly one opengl32.dll, found $($candidates.Count)" }
    $dll = $candidates[0].FullName
    # Confirm PE machine architecture before injection into the JVM directory.
    $stream = [IO.File]::OpenRead($dll)
    try {
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Mesa DLL: invalid MZ header' }
        $stream.Position = 0x3C
        $offset = $reader.ReadInt32()
        if ($offset -lt 0x40 -or $offset -gt $stream.Length - 6) { throw 'Mesa DLL: invalid PE offset' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Mesa DLL: invalid PE signature' }
        if ($reader.ReadUInt16() -ne $peMachine) { throw 'Mesa DLL: PE machine does not match Java architecture' }
    } finally { $stream.Dispose() }
    $destination = Join-Path $runtimeDirectory 'opengl32.dll'
    # This is a CI-managed JDK, not a user's installation. Do not overwrite an
    # existing JDK DLL; if it is present, the reason must be investigated.
    if (Test-Path -LiteralPath $destination) { throw "JDK directory already contains opengl32.dll: $destination" }
    Copy-Item -LiteralPath $dll -Destination $destination
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash -cne (Get-FileHash -Algorithm SHA256 -LiteralPath $dll).Hash) {
        throw 'Installed Mesa OpenGL DLL checksum mismatch'
    }
    Write-Host "Pinned Mesa $mesaVersion llvmpipe installed for $arch in disposable JDK"
} finally {
    Remove-Item -LiteralPath $work -Force -Recurse -ErrorAction SilentlyContinue
}
