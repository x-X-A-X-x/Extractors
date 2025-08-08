# Path to your Windows Firewall log
$logPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

# Check if log file exists
if (-not (Test-Path $logPath)) {
    Write-Host "Log file not found: $logPath" -ForegroundColor Red
    exit
}

# Read the log and skip comment/header lines starting with #
$lines = Get-Content $logPath | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }

$parsedEntries = foreach ($line in $lines) {
    # Split on whitespace
    $fields = $line -split '\s+'
    
    # Ensure we have enough fields before processing
    if ($fields.Length -ge 17) {
        $pid = $fields[16]

        # Try to get process name from PID
        $procName = try {
            (Get-Process -Id $pid -ErrorAction Stop).ProcessName
        } catch {
            "N/A"
        }

        # Build structured object
        [PSCustomObject]@{
            date        = $fields[0]
            time        = $fields[1]
            action      = $fields[2]
            protocol    = $fields[3]
            src_ip      = $fields[4]
            dst_ip      = $fields[5]
            src_port    = $fields[6]
            dst_port    = $fields[7]
            size        = $fields[8]
            tcpflags    = $fields[9]
            tcpsyn      = $fields[10]
            tcpack      = $fields[11]
            tcpwin      = $fields[12]
            icmptype    = $fields[13]
            icmpcode    = $fields[14]
            info        = $fields[15]
            pid         = $pid
            processname = $procName
        }
    }
}

# Output CSV for SIEM ingestion
$outFile = "$env:USERPROFILE\Desktop\firewall_with_process.csv"
$parsedEntries | Export-Csv $outFile -NoTypeInformation

Write-Host "Exported parsed firewall log to $outFile" -ForegroundColor Green
