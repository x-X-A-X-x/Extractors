<# 
Extract Windows Event Logs into Splunk-friendly CSVs.
- One CSV per log: System, Application, Security, Setup
- Stable columns: common metadata + auto-expanded EventData keys
- Timestamps in ISO 8601
#>

[CmdletBinding()]
param(
    [string[]]$Logs = @('System','Application','Security','Setup'),
    [datetime]$StartTime = (Get-Date).AddDays(-7),
    [datetime]$EndTime   = (Get-Date),
    [string]$ExportPath  = $PSScriptRoot  # default: script folder
)

if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath | Out-Null
}

foreach ($Log in $Logs) {
    Write-Host "`nExtracting $Log ..."

    try {
        # First pass: collect union of all EventData keys for a stable CSV header
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

        # Sort keys for stable column order
        $eventDataKeys = $allKeys | Sort-Object

        # Second pass: build rows with consistent schema
        $rows = foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()

            # Map EventData into a dictionary
            $kv = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $name = [string]$d.Name
                if ($name) { $kv[$name] = [string]$d.'#text' }
            }

            # Common metadata
            [pscustomobject]@{
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
                # EventData keys expanded below
            } | ForEach-Object {
                $base = $_ | Select-Object *  # clone PSCustomObject
                foreach ($k in $eventDataKeys) {
                    # Add property per key; empty if not present in this event
                    Add-Member -InputObject $base -NotePropertyName $k -NotePropertyValue ($kv[$k]) -Force
                }
                $base
            }
        }

        $outFile = Join-Path $ExportPath ("{0}_Logs.csv" -f $Log)
        if ($rows.Count -gt 0) {
            # Export with a stable header (metadata first, then EventData keys)
            # Compute explicit column order
            $metaColumns = @(
                'TimeCreatedISO','EventID','Level','LevelDisplayName','ProviderName','MachineName',
                'Channel','RecordId','Task','Opcode','Keywords','ProcessId','ThreadId','UserId','SourceLog','Message'
            )
            $allColumns = $metaColumns + $eventDataKeys
            $rows | Select-Object $allColumns | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
            Write-Host ("Exported {0} events to: {1}" -f $rows.Count, $outFile)
        }
        else {
            Write-Host "No events found for the specified time range."
        }
    }
    catch {
        Write-Host ("Failed to extract {0}: {1}" -f $Log, $_.Exception.Message)
    }
}
