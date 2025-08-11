<#
EvtxToJson_Splunk.ps1
Reads .evtx files from C:\Windows\System32\winevt\Logs and writes NDJSON per log.
Designed for Splunk (set sourcetype=_json on the monitored folder).

Examples:
  .\EvtxToJson_Splunk.ps1
  .\EvtxToJson_Splunk.ps1 -OutDir "C:\Logs\Json"
  .\EvtxToJson_Splunk.ps1 -NoMessageFormat
#>

[CmdletBinding()]
param(
  [string]$SourceDir = "C:\Windows\System32\winevt\Logs",
  [string[]]$Logs = @("Application","Security","System","Setup"),
  [string]$OutDir = $PSScriptRoot,
  [switch]$NoMessageFormat, # skip FormatDescription() for speed/robustness
  [switch]$Oldest,          # iterate from oldest to newest
  [switch]$VerboseSummary
)

function Test-IsAdmin {
  try {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  } catch { return $false }
}

function Convert-WinEventToJsonObject {
  param(
    [System.Diagnostics.Eventing.Reader.EventRecord]$Event,
    [switch]$NoFmt
  )

  $xml = [xml]$Event.ToXml()

  # Flatten EventData <Data Name="...">value</Data>
  $eventData = @{}
  foreach ($d in $xml.Event.EventData.Data) {
    if ($null -ne $d) {
      $name = [string]$d.Name
      if (-not [string]::IsNullOrWhiteSpace($name)) {
        $eventData[$name] = [string]$d.'#text'
      }
    }
  }

  # Safe message formatting (may throw for some events)
  $msg = $null
  if (-not $NoFmt) {
    try { $msg = $Event.FormatDescription() } catch { $msg = $null }
  }

  $obj = [ordered]@{
    _time          = [int](Get-Date $Event.TimeCreated -UFormat %s)
    TimeCreated    = $Event.TimeCreated
    LogName        = $Event.LogName
    EventID        = $Event.Id
    Level          = $Event.Level
    LevelDisplay   = $Event.LevelDisplayName
    ProviderName   = $Event.ProviderName
    MachineName    = $Event.MachineName
    RecordId       = $Event.RecordId
    ProcessId      = [string]$xml.Event.System.Execution.ProcessID
    ThreadId       = [string]$xml.Event.System.Execution.ThreadID
    Keywords       = [string]$xml.Event.System.Keywords
    Task           = [string]$xml.Event.System.Task
    Opcode         = [string]$xml.Event.System.Opcode
    Channel        = [string]$xml.Event.System.Channel
    SecurityUserId = [string]$xml.Event.System.Security.UserID
    Correlation    = [string]$xml.Event.System.Correlation.ActivityID
    Message        = $msg
    EventData      = $eventData
  }

  foreach ($k in $eventData.Keys) {
    if (-not $obj.ContainsKey($k)) { $obj[$k] = $eventData[$k] }
  }

  return [pscustomobject]$obj
}

# Validate source
if (-not (Test-Path -LiteralPath $SourceDir)) {
  throw "SourceDir not found: $SourceDir"
}

# Ensure output dir
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = $PSScriptRoot }
if (-not (Test-Path -LiteralPath $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
}

if (-not (Test-IsAdmin)) {
  Write-Host "Warning: Not running as Administrator. Reading Security.evtx may fail or return fewer events."
}

$summary = @()

foreach ($log in $Logs) {
  $evtxPath = Join-Path $SourceDir ($log + ".evtx")
  if (-not (Test-Path -LiteralPath $evtxPath)) {
    Write-Host ("Skipping {0} (file not found): {1}" -f $log, $evtxPath)
    continue
  }

  $safeName = ($log -replace '[\\/:*?"<>|]', '_')
  $outFile = Join-Path $OutDir ("{0}_from_evtx.json" -f $safeName)

  Write-Host ("Reading {0}" -f $evtxPath)

  $sw = $null
  $written = 0
  try {
    $sw = New-Object System.IO.StreamWriter($outFile, $false, [System.Text.Encoding]::UTF8)

    if ($Oldest) {
      Get-WinEvent -Path $evtxPath -Oldest -ErrorAction Stop | ForEach-Object {
        $obj  = Convert-WinEventToJsonObject -Event $_ -NoFmt:$NoMessageFormat
        $json = $obj | ConvertTo-Json -Depth 6 -Compress
        $sw.WriteLine($json); $written++
      }
    } else {
      Get-WinEvent -Path $evtxPath -ErrorAction Stop | ForEach-Object {
        $obj  = Convert-WinEventToJsonObject -Event $_ -NoFmt:$NoMessageFormat
        $json = $obj | ConvertTo-Json -Depth 6 -Compress
        $sw.WriteLine($json); $written++
      }
    }

    $sw.Close()
    Write-Host ("Wrote {0} events to {1}" -f $written, $outFile)
  }
  catch {
    if ($sw) { $sw.Close() }
    Write-Host ("Failed to process {0}: {1}" -f $evtxPath, $_.Exception.Message)
  }

  $summary += [pscustomobject]@{
    LogName       = $log
    EvtxFile      = $evtxPath
    ExportedCount = $written
    OutputFile    = $outFile
  }
}

Write-Host ""
Write-Host "Summary"
$summary | Format-Table -AutoSize

if ($VerboseSummary) {
  Write-Host ""
  foreach ($row in $summary) {
    "{0,-12}  Exported={1,-8}  {2}" -f $row.LogName, $row.ExportedCount, $row.OutputFile
  }
}

Write-Host ""
Write-Host "Tip: In Splunk, monitor $OutDir and set sourcetype=_json for automatic field extraction."
