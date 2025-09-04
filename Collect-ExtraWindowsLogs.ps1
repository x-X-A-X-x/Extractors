<# 
Collect-ExtraWindowsLogs.ps1
Exports selected Windows "additional" logs (beyond DNS/System/Setup/Security/Application/Firewall)
to EVTX + JSONL. Defaults to current script directory. Run elevated.

Usage:
  powershell -ExecutionPolicy Bypass -File .\Collect-ExtraWindowsLogs.ps1 -Days 7
  # optional custom out folder:
  powershell -ExecutionPolicy Bypass -File .\Collect-ExtraWindowsLogs.ps1 -Days 3 -OutDir "D:\HostLogs"

#>

[CmdletBinding()]
param(
  [int]$Days = 7,
  [string]$OutDir = $PSScriptRoot
)

# --- auto-elevate ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
  Write-Host "[*] Elevation required, relaunching as Administrator..."
  Start-Process -FilePath "powershell.exe" -Verb RunAs `
    -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -Days $Days -OutDir `"$OutDir`""
  exit
}

# --- target log names (additional high-value) ---
# Note: Only logs present on the host will be collected.
$TargetLogs = @(
  # Security & admin tooling
  'Microsoft-Windows-PowerShell/Operational'
  'Microsoft-Windows-WMI-Activity/Operational'
  'Microsoft-Windows-TaskScheduler/Operational'
  'Microsoft-Windows-GroupPolicy/Operational'
  'Microsoft-Windows-Windows Defender/Operational'
  'Microsoft-Windows-BitLocker/BitLocker Management'
  # Networking & access
  'Microsoft-Windows-DHCP-Client/Admin'
  'Microsoft-Windows-TCPIP/Operational'
  'Microsoft-Windows-NetworkProfile/Operational'
  'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
  # Sysmon (if installed)
  'Microsoft-Windows-Sysmon/Operational'
  # Printing (sometimes used for LM/lat-move tricks)
  'Microsoft-Windows-PrintService/Operational'
  # Reliability/diagnostics
  'Microsoft-Windows-Kernel-Boot'
  'Microsoft-Windows-Kernel-Power'
  'Microsoft-Windows-Diagnostics-Performance/Operational'
  # Misc
  'ForwardedEvents'
  'HardwareEvents'
)

# Make sure output folder exists
if (-not (Test-Path -LiteralPath $OutDir)) {
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

$StartTime = (Get-Date).AddDays(-1 * [math]::Abs($Days))
$EndTime   = Get-Date

# Get installed log names once for existence checks
try {
  $ExistingLogs = & wevtutil el 2>$null
} catch {
  Write-Warning "wevtutil not available? Falling back to Get-WinEvent without pre-check."
  $ExistingLogs = @()
}

function Export-Log {
  param(
    [Parameter(Mandatory=$true)][string]$LogName,
    [Parameter(Mandatory=$true)][datetime]$Start,
    [Parameter(Mandatory=$true)][datetime]$End,
    [Parameter(Mandatory=$true)][string]$Folder
  )

  $safeName = ($LogName -replace '[\\/\s:]','_')
  $evtxPath = Join-Path $Folder "$safeName.evtx"
  $jsonlPath = Join-Path $Folder "$safeName.jsonl"

  Write-Host "==> $LogName"

  # Export EVTX (best-effort)
  try {
    & wevtutil epl "$LogName" "$evtxPath" /q:"*[System[TimeCreated[@SystemTime>='$($Start.ToUniversalTime().ToString("o"))' and @SystemTime<='$($End.ToUniversalTime().ToString("o"))']]]" 2>$null
    if (Test-Path $evtxPath) { Write-Host "    EVTX: $evtxPath" } else { Write-Warning "    EVTX export produced no file (maybe no events in range)"; }
  } catch {
    Write-Warning "    EVTX export failed: $($_.Exception.Message)"
  }

  # Export JSONL
  try {
    $filter = @{
      LogName   = $LogName
      StartTime = $Start
      EndTime   = $End
    }
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop

    if ($events.Count -gt 0) {
      # Stream to JSONL
      $file = [System.IO.StreamWriter]::new($jsonlPath, $false, [System.Text.Encoding]::UTF8)
      try {
        foreach ($e in $events) {
          $xml = [xml]$e.ToXml()
          $obj = [PSCustomObject]@{
            LogName            = $e.LogName
            ProviderName       = $e.ProviderName
            Id                 = $e.Id
            Level              = $e.Level
            LevelDisplayName   = $e.LevelDisplayName
            Task               = $e.Task
            OpcodeDisplayName  = $e.OpcodeDisplayName
            KeywordsDisplay    = $e.KeywordsDisplayNames
            TimeCreated        = $e.TimeCreated
            RecordId           = $e.RecordId
            MachineName        = $e.MachineName
            ProcessId          = $e.ProcessId
            ThreadId           = $e.ThreadId
            Message            = $e.Message
            Properties         = $e.Properties.Value
            # Raw XML for full fidelity parsing later if needed
            EventXml           = $xml.OuterXml
          }
          # Convert to compressed JSON and ensure single-line (JSONL)
          $line = ($obj | ConvertTo-Json -Compress)
          $file.WriteLine($line)
        }
      } finally {
        $file.Close()
      }
      Write-Host "    JSONL: $jsonlPath  ($($events.Count) events)"
    } else {
      Write-Host "    JSONL: no events in range"
    }
  } catch {
    Write-Warning "    JSONL export failed: $($_.Exception.Message)"
  }
}

Write-Host "[*] Collecting events from $($StartTime) to $($EndTime) ..."
Write-Host "[*] Output folder: $OutDir"
Write-Host ""

foreach ($log in $TargetLogs) {
  $exists = $true
  if ($ExistingLogs -and ($ExistingLogs -notcontains $log)) { $exists = $false }
  if (-not $exists) {
    Write-Host "-- skipping (log not present): $log"
    continue
  }

  Export-Log -LogName $log -Start $StartTime -End $EndTime -Folder $OutDir
}

Write-Host ""
Write-Host "[✓] Done."
