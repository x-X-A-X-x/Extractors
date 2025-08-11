<#
Exports Windows Event Logs as JSON Lines (NDJSON), one file per log.
Designed for Splunk (sourcetype=_json). Promotes EventData keys to top level.

Examples:
  .\ELExtract_SplunkJSON.ps1 -All -Oldest
  .\ELExtract_SplunkJSON.ps1 -DaysBack 30
  .\ELExtract_SplunkJSON.ps1 -Logs Security,System -OutDir C:\Logs -NoMessageFormat
#>

[CmdletBinding()]
param(
  [string[]]$Logs = @(
    "System","Application","Security","Setup",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-DNS-Client/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TaskScheduler/Operational"
  ),

  [int]$DaysBack = 7,

  [datetime]$StartTime,

  [datetime]$EndTime = (Get-Date),

  [string]$OutDir = $PSScriptRoot,

  [switch]$All,            # ignore Start/End; export entire current log
  [switch]$Oldest,         # iterate from oldest record forward
  [switch]$NoMessageFormat,# do not call FormatDescription()
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
  param([System.Diagnostics.Eventing.Reader.EventRecord]$Event, [switch]$NoFmt)

  $xml = [xml]$Event.ToXml()

  # Flatten EventData
  $eventData = @{}
  foreach ($d in $xml.Event.EventData.Data) {
    if ($null -ne $d) {
      $name = [string]$d.Name
      if (-not [string]::IsNullOrWhiteSpace($name)) {
        $eventData[$name] = [string]$d.'#text'
      }
    }
  }

  # Safe message formatting
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

# Resolve time window unless -All specified
if (-not $All) {
  if (-not $PSBoundParameters.ContainsKey('StartTime')) {
    $StartTime = (Get-Date).AddDays(-1 * $DaysBack)
  }
}

# Ensure output dir
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = $PSScriptRoot }
if (-not (Test-Path -LiteralPath $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
}

# Admin warning
if (-not (Test-IsAdmin)) {
  Write-Host "Warning: Not running as Administrator. Security and some channels may not return all events."
}

# Pre-flight: get channel info
$channelInfo = @{}
foreach ($log in $Logs) {
  try {
    $li = Get-WinEvent -ListLog $log -ErrorAction Stop
    $channelInfo[$log] = $li
  } catch {
    $channelInfo[$log] = $null
    Write-Host ("Channel not found or inaccessible: {0}" -f $log)
  }
}

# Extract per log
$summary = @()
foreach ($log in $Logs) {
  $li = $channelInfo[$log]
  if ($null -eq $li) { continue }

  if (-not $li.IsEnabled) {
    Write-Host ("Channel disabled: {0}. Enable with: wevtutil sl `"{0}`" /e:true" -f $log)
  }

  $outFile = Join-Path $OutDir ("{0}_Logs.json" -f ($log -replace '[\\/:*?"<>|]', '_'))
  Write-Host ("Extracting {0} ..." -f $log)

  $sw = $null
  $written = 0
  try {
    $sw = New-Object System.IO.StreamWriter($outFile, $false, [System.Text.Encoding]::UTF8)

    if ($All) {
      # No time filter; optionally iterate from oldest
      if ($Oldest) {
        Get-WinEvent -LogName $log -Oldest -ErrorAction Stop | ForEach-Object {
          $obj  = Convert-WinEventToJsonObject -Event $_ -NoFmt:$NoMessageFormat
          $json = $obj | ConvertTo-Json -Depth 6 -Compress
          $sw.WriteLine($json); $written++
        }
      } else {
        Get-WinEvent -LogName $log -ErrorAction Stop | ForEach-Object {
          $obj  = Convert-WinEventToJsonObject -Event $_ -NoFmt:$NoMessageFormat
          $json = $obj | ConvertTo-Json -Depth 6 -Compress
          $sw.WriteLine($json); $written++
        }
      }
    } else {
      $query = @{ LogName = $log; StartTime = $StartTime; EndTime = $EndTime }
      if ($Oldest) {
        Get-WinEvent -FilterHashtable $query -Oldest -ErrorAction Stop | ForEach-Object {
          $obj  = Convert-WinEventToJsonObject -Event $_ -NoFmt:$NoMessageFormat
          $json = $obj | ConvertTo-Json -Depth 6 -Compress
          $sw.WriteLine($json); $written++
        }
      } else {
        Get-WinEvent -FilterHashtable $query -ErrorAction Stop | ForEach-Object {
          $obj  = Convert-WinEventToJsonObject -Event $_ -NoFmt:$NoMessageFormat
          $json = $obj | ConvertTo-Json -Depth 6 -Compress
          $sw.WriteLine($json); $written++
        }
      }
    }

    $sw.Close()
    Write-Host ("Wrote {0} events to {1}" -f $written, $outFile)
  }
  catch {
    if ($sw) { $sw.Close() }
    Write-Host ("Failed to extract {0}: {1}" -f $log, $_.Exception.Message)
  }

  $summary += [pscustomobject]@{
    LogName          = $log
    ChannelEnabled   = $li.IsEnabled
    RecordCountTotal = $li.RecordCount
    ExportedCount    = $written
    OutputFile       = $outFile
  }
}

# Summary
Write-Host ""
Write-Host "Summary"
$summary | Format-Table -AutoSize

if ($VerboseSummary) {
  Write-Host ""
  Write-Host "Channel details"
  foreach ($log in $Logs) {
    $li = $channelInfo[$log]
    if ($li) {
      "{0,-70} Enabled={1}  Records={2}  MaxSizeBytes={3}" -f $log, $li.IsEnabled, $li.RecordCount, $li.MaximumSizeInBytes
    } else {
      "{0,-70} not found/inaccessible" -f $log
    }
  }
}

Write-Host ""
Write-Host "Tip: In Splunk, monitor the output folder and set sourcetype=_json for automatic field extraction."
