<#
ELExtract_SplunkJSON.ps1
Exports Windows Event Logs as JSON Lines (NDJSON) per log so Splunk can auto-extract fields.
Default logs: System, Application, Security, Setup
Default range: last 7 days
Outputs: <LogName>_Logs.json in the script folder

Examples:
  .\ELExtract_SplunkJSON.ps1
  .\ELExtract_SplunkJSON.ps1 -Logs Security -DaysBack 1 -OutDir "C:\Logs"
#>

[CmdletBinding()]
param(
  [Parameter(ValueFromPipeline = $false)]
  [string[]]$Logs = @("System","Application","Security","Setup"),

  [int]$DaysBack = 7,

  [datetime]$StartTime = (Get-Date).AddDays(-1 * $DaysBack),

  [datetime]$EndTime = (Get-Date),

  [string]$OutDir = $PSScriptRoot
)

function Convert-WinEventToJsonObject {
  param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

  # Parse XML for rich fields + EventData
  $xml = [xml]$Event.ToXml()

  # Flatten EventData <Data Name="...">value</Data> into a hashtable
  $eventData = @{}
  foreach ($d in $xml.Event.EventData.Data) {
    if ($null -ne $d) {
      $name = [string]$d.Name
      if (-not [string]::IsNullOrWhiteSpace($name)) {
        $eventData[$name] = [string]$d.'#text'
      }
    }
  }

  # Core fields (Execution attributes are ProcessID/ThreadID)
  $obj = [ordered]@{
    _time          = [int](Get-Date $Event.TimeCreated -UFormat %s)   # epoch secs for Splunk
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
    Message        = $Event.FormatDescription()
    EventData      = $eventData
  }

  # Promote EventData keys to top-level for easier Splunk search (avoid collisions)
  foreach ($k in $eventData.Keys) {
    if (-not $obj.ContainsKey($k)) {
      $obj[$k] = $eventData[$k]
    }
  }

  return [pscustomobject]$obj
}

# Ensure output directory
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = $PSScriptRoot }
if (-not (Test-Path -LiteralPath $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
}

foreach ($log in $Logs) {
  $outFile = Join-Path $OutDir ("{0}_Logs.json" -f $log)
  Write-Host ("Extracting {0} from {1:u} to {2:u} ..." -f $log, $StartTime, $EndTime)

  $sw = $null
  try {
    # Stream to file as NDJSON (one JSON object per line)
    $sw = New-Object System.IO.StreamWriter($outFile, $false, [System.Text.Encoding]::UTF8)

    $query = @{
      LogName   = $log
      StartTime = $StartTime
      EndTime   = $EndTime
    }

    Get-WinEvent -FilterHashtable $query -ErrorAction Stop | ForEach-Object {
      $obj  = Convert-WinEventToJsonObject -Event $_
      $json = $obj | ConvertTo-Json -Depth 6 -Compress
      $sw.WriteLine($json)
    }

    $sw.Close()
    Write-Host ("Wrote {0}" -f $outFile)
  }
  catch {
    if ($sw) { $sw.Close() }
    Write-Host ("Failed to extract {0}: {1}" -f $log, $_.Exception.Message)
  }
}
