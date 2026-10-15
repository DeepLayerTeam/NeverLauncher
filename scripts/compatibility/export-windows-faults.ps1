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
[System.IO.File]::WriteAllLines($OutputPath, $lines)
