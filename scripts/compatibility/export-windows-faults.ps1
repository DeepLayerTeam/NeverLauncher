param(
  [Parameter(Mandatory = $true)]
  [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }

# Export *metadata only*. Do not upload WER minidumps from public CI: process
# dumps can contain auth tokens, credentials and other user/application secrets.
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
    # Standard Application Error (1000): failing executable, module, version,
    # exception code, fault offset. Never print arbitrary WER free-text fields.
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
