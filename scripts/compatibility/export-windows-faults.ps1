param(
  [Parameter(Mandatory = $true)]
  [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }

# Экспортируйте только метаданные. Не загружайте minidump WER из публичного CI: дампы содержат
# токены аутентификации, учётные данные и другие секреты пользователя или приложения.
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('NeverLauncher public-CI Windows native fault summary (no memory dumps)')
try {
  $events = @(Get-WinEvent -FilterHashtable @{
      LogName = 'Application'
      Id = @(1000, 1001)
      StartTime = (Get-Date).AddMinutes(-90)
    } -MaxEvents 200 -ErrorAction Stop)
  $matched = 0
  foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $values = @($xml.Event.EventData.Data | ForEach-Object { [string]$_.InnerText })
    if (-not (($values -join ' ') -match '(?i)\bjavaw?\.exe\b')) { continue }
    $lines.Add("TimeUTC=$($event.TimeCreated.ToUniversalTime().ToString('o')) EventID=$($event.Id) Provider=$($event.ProviderName)")
    # Стандартная ошибка приложения (1000): исполняемый файл, модуль, версия, код
    # исключения и смещение сбоя. Не выводите произвольные свободные текстовые поля WER.
    if ($event.Id -eq 1000 -and $values.Count -ge 8) {
      foreach ($i in @(0, 3, 6, 7)) {
        $value = $values[$i]
        if ($value.Length -gt 260) { $value = $value.Substring(0, 260) }
        $lines.Add("  Field$($i)=$value")
      }
    } else {
      $lines.Add('  Windows Error Reporting event present (fields omitted)')
    }
    $matched++
    if ($matched -ge 15) { break }
  }
  if ($matched -eq 0) { $lines.Add('No Java Application Error/WER event found in the last 90 minutes.') }
} catch {
  $lines.Add('Windows Application Event Log unavailable on this runner.')
}
# Event Log access is restricted on some GitHub-hosted runners. Windows Error
# Reporting also stores a small UTF-16 text report alongside private dumps.
# Read ONLY four whitelisted signature values. Never publish report paths,
# arbitrary WER text, memory dumps, loaded-module lists or command lines.
try {
  $folders = @()
  foreach ($base in @(
      (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'),
      (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue')
    )) {
    if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
    $folders += @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match '^(?i:(AppCrash|BEX64|BEX))_javaw?\.exe_' })
  }
  $found = 0
  foreach ($folder in @($folders | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 20)) {
    if ($folder.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddMinutes(-90)) { continue }
    foreach ($report in @(Get-ChildItem -LiteralPath $folder.FullName -File -Filter '*.wer' -ErrorAction SilentlyContinue | Select-Object -First 1)) {
      $pairs = @{}
      $key = ''
      foreach ($line in @(Get-Content -LiteralPath $report.FullName -ErrorAction SilentlyContinue)) {
        if ($line -match '^Sig\[([0-9]{1,2})\]\.Name=(.*)$') {
          $key = $Matches[1]
          $pairs["name_$key"] = $Matches[2]
        } elseif ($line -match '^Sig\[([0-9]{1,2})\]\.Value=(.*)$') {
          $pairs["value_$($Matches[1])"] = $Matches[2]
        }
      }
      $safe = @{}
      for ($i = 0; $i -lt 32; $i++) {
        $label = $pairs["name_$i"]
        if ($label -in @('Application Name', 'Fault Module Name', 'Exception Code', 'Exception Offset')) {
          $value = [string]$pairs["value_$i"]
          if ($value -match '^[a-zA-Z0-9_.+-]{1,128}$') { $safe[$label] = $value }
        }
      }
      if ($safe.ContainsKey('Application Name') -and $safe['Application Name'] -notmatch '^(?i:javaw?\.exe)$') { continue }
      if ($safe.Count -gt 0) {
        $lines.Add('WER Java native crash (signature metadata only):')
        foreach ($label in @('Application Name', 'Fault Module Name', 'Exception Code', 'Exception Offset')) {
          if ($safe.ContainsKey($label)) { $lines.Add("  $label=$($safe[$label])") }
        }
        $found++
      }
    }
  }
  if ($found -eq 0) { $lines.Add('No readable Java WER signature reports in the last 90 minutes.') }
} catch {
  $lines.Add('Windows WER signature report store unavailable on this runner.')
}
[System.IO.File]::WriteAllLines($OutputPath, $lines)
