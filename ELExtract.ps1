<# 
Extract Windows Event Logs into Splunk-friendly CSVs (one file per log).
- Stable columns (metadata + expanded EventData keys)
- ISO 8601 timestamps
- Robust ExportPath resolution
#>

[CmdletBinding()]
param(
    [string[]]$Logs = @('System','Application','Security','Setup'),
    [datetime]$StartTime = (Get-Date).AddDays(-7),
    [datetime]$EndTime   = (Get-Date),
    [string]$ExportPath  # optional; if omitted, use script folder; fallback: current dir
)

# --- Resolve ExportPath robustly ---
if ([string]::IsNullOrWhiteSpace($ExportPath)) {
    # Try the script’s directory first
    $ExportPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Path
    # Fallback to current directory if still empty (e.g., rare host scenarios)
    if ([string]::IsNullOrWhiteSpace($ExportPath)) {
        $ExportPath = (Get-Location).Path
    }
}

if (-not (Test-Path -LiteralPath $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

foreach ($Log in $Logs) {
    Write-Host "`nExtracting $Log ..."
    try {
        # First pass: gather union of EventData keys for stable header
        $allKeys = [System.Collections.Generic.HashSet[string]]::new()
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $Log
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop

        foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $null = $allKeys.Add([string]$d.Name) }
            }
        }

        $eventDataKeys = $allKeys | Sort-Object

        # Second pass: build rows with consistent schema
        $rows = foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()

            $kv = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $name = [string]$d.Name
                if ($name) { $kv[$name] = [string]$d.'#text' }
            }

            # Common metadata (good for Splunk)
            $base = [pscustomobject]@{
                TimeCreatedISO      = $ev.TimeCreated.ToString("o")
                EventID             = $ev.Id
                Level               = $ev.Level
                LevelDisplayName    = $ev.LevelDisplayName
                ProviderName        = $ev.ProviderName
                MachineName         = $ev.MachineName
                Channel             = $ev.LogName
                RecordId            = $ev.RecordId
                Task                = $ev.Task
                Opcode              = $ev.Opcode
                Keywords            = $ev.Keywords
                ProcessId           = $ev.ProcessId
                ThreadId            = $ev.ThreadId
                UserId              = $ev.UserId
                SourceLog           = $Log
                Message             = $ev.Message
            }

            foreach ($k in $eventDataKeys) {
                Add-Member -InputObject $base -NotePropertyName $k -NotePropertyValue ($kv[$k]) -Force
            }
            $base
        }

        $outFile = Join-Path -Path $ExportPath -ChildPath ("{0}_Logs.csv" -f $Log)
        if ($rows.Count -gt 0) {
            $metaColumns = @(
                'TimeCreatedISO','EventID','Level','LevelDisplayName','ProviderName','MachineName',
                'Channel','RecordId','Task','Opcode','Keywords','ProcessId','ThreadId','UserId','SourceLog','Message'
            )
            $allColumns = $metaColumns + $eventDataKeys
            $rows | Select-Object $allColumns | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
            Write-Host ("Exported {0} events to: {1}" -f $rows.Count, $outFile)
        } else {
            Write-Host "No events found for the specified time range."
        }
    }
    catch {
        Write-Host ("Failed to extract {0}: {1}" -f $Log, $_.Exception.Message)
    }
}
