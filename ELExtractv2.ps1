<# 
Exports Windows logs (Application, Security, Setup, System) to EVTX and Splunk-friendly JSONL.
Run in elevated PowerShell for Security log access.
Do "powershell -ExecutionPolicy Bypass -File .\ELExtractv2.ps1" on powershell to run this too, this is for sec purposes only
#>

[CmdletBinding()]
param(
    [string[]]$Channels = @('Application','Security','Setup','System'),
    [int]$Days = 7,
    [string]$OutDir = $PSScriptRoot
)

# Create output folder
if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

$StartTime = (Get-Date).AddDays(-1 * [math]::Abs($Days))
$EndTime   = Get-Date

foreach ($ch in $Channels) {
    Write-Host "`nChannel: $ch"

    # 1) EVTX archive (exact copy of the channel)
    $evtx = Join-Path $OutDir "$ch.evtx"
    try {
        wevtutil epl $ch $evtx
        Write-Host "EVTX exported: $evtx"
    } catch {
        Write-Host ("EVTX export failed for {0}: {1}" -f $ch, $_.Exception.Message)
    }

    # 2) JSONL for Splunk (one JSON object per line)
    $jsonPath = Join-Path $OutDir "$ch.json"
    try {
        # Pull events in the time range
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $ch
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop

        # Build JSON objects with expanded EventData
        $out = New-Object System.Collections.Generic.List[string]
        $i = 0
        $total = $events.Count

        foreach ($ev in $events) {
            $i++
            if ($i % 1000 -eq 0) {
                Write-Progress -Activity "Building JSON ($ch)" -Status "$i / $total" -PercentComplete (($i/$total)*100)
            }

            $xml = [xml]$ev.ToXml()
            $kv = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $name = [string]$d.Name
                if ($name) { $kv[$name] = [string]$d.'#text' }
            }

            $obj = [pscustomobject]@{
                TimeCreatedISO   = $ev.TimeCreated.ToString("o")  # Splunk-friendly timestamp
                EventID          = $ev.Id
                Level            = $ev.Level
                LevelDisplayName = $ev.LevelDisplayName
                ProviderName     = $ev.ProviderName
                Computer         = $ev.MachineName
                Channel          = $ev.LogName
                RecordId         = $ev.RecordId
                Task             = $ev.Task
                Opcode           = $ev.Opcode
                Keywords         = $ev.Keywords
                ProcessId        = $ev.ProcessId
                ThreadId         = $ev.ThreadId
                UserSid          = $ev.UserId
                Message          = $ev.Message
                SourceLog        = $ch
                EventData        = $kv            # nested dict of all EventData keys/values
            }

            # One JSON object per line
            $out.Add( ($obj | ConvertTo-Json -Depth 6 -Compress) )
        }

        # Write JSONL
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($jsonPath, $out, $utf8NoBom)
        Write-Host "JSON exported:  $jsonPath  ($($events.Count) events)"
    } catch {
        Write-Host ("JSON export failed for {0}: {1}" -f $ch, $_.Exception.Message)
    }
}
