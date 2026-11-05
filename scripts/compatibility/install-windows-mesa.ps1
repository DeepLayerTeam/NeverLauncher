# В Windows-агентах GitHub нет современного OpenGL ICD. Устанавливайте известную
# Mesa llvmpipe WGL с закреплённым SHA-256 только во временный JDK CI-агента.
# Источник: https://github.com/mmozeiko/build-mesa/releases/tag/26.2.4. Никогда
# не используйте это для производственного лаунчера или обхода античита.
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
if ([IO.Path]::GetFileName($javaPath) -ine 'java.exe') { throw 'Ожидался java.exe закреплённой версии JDK' }
$runtimeDirectory = Split-Path -Parent $javaPath
$name = "mesa-llvmpipe-$arch-$mesaVersion.7z"
$url = "https://github.com/mmozeiko/build-mesa/releases/download/$mesaVersion/$name"
$work = Join-Path $env:RUNNER_TEMP ("launcher-mesa-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $archive = Join-Path $work $name
    # Повторяйте временные ошибки внешнего сервиса, но никогда не принимайте изменившиеся байты.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try { Invoke-WebRequest -Uri $url -OutFile $archive -MaximumRedirection 5; break }
        catch { if ($attempt -eq 3) { throw }; Start-Sleep -Seconds (2 * $attempt) }
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -cne $hashes[$arch]) { throw "Контрольная сумма архива Mesa для ${arch} не совпадает: $actual" }
    $sevenZip = Get-Command '7z.exe' -ErrorAction SilentlyContinue
    if (-not $sevenZip) { throw 'На Windows-агенте GitHub отсутствует 7z.exe' }
    $unpack = Join-Path $work 'unpack'
    New-Item -ItemType Directory -Force -Path $unpack | Out-Null
    & $sevenZip.Source x '-y' "-o$unpack" $archive | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Распаковка через 7z завершилась ошибкой: $LASTEXITCODE" }
    $candidates = @(Get-ChildItem -Path $unpack -File -Recurse -Filter opengl32.dll)
    if ($candidates.Count -ne 1) { throw "Пакет Mesa должен содержать ровно один opengl32.dll; найдено: $($candidates.Count)" }
    $dll = $candidates[0].FullName
    # Проверяйте архитектуру PE до добавления в каталог JVM.
    $stream = [IO.File]::OpenRead($dll)
    try {
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'DLL Mesa: неверный заголовок MZ' }
        $stream.Position = 0x3C
        $offset = $reader.ReadInt32()
        if ($offset -lt 0x40 -or $offset -gt $stream.Length - 6) { throw 'DLL Mesa: неверное смещение PE' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'DLL Mesa: неверная сигнатура PE' }
        if ($reader.ReadUInt16() -ne $peMachine) { throw 'DLL Mesa: архитектура PE не соответствует архитектуре Java' }
    } finally { $stream.Dispose() }
    $destination = Join-Path $runtimeDirectory 'opengl32.dll'
    # Это JDK под управлением CI, не пользовательская установка. Не
    # перезаписывайте существующую DLL JDK; если она есть, нужно выяснить причину.
    if (Test-Path -LiteralPath $destination) { throw "Каталог JDK уже содержит opengl32.dll: $destination" }
    Copy-Item -LiteralPath $dll -Destination $destination
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash -cne (Get-FileHash -Algorithm SHA256 -LiteralPath $dll).Hash) {
        throw 'Контрольная сумма установленной DLL Mesa OpenGL не совпадает'
    }
    Write-Host "Закреплённая версия Mesa $mesaVersion (llvmpipe) установлена для $arch во временную JDK"
} finally {
    Remove-Item -LiteralPath $work -Force -Recurse -ErrorAction SilentlyContinue
}
