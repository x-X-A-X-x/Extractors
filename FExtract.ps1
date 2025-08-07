# Set log file path (edit if using custom location)
$logPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

# Check if file exists
if (-Not (Test-Path $logPath)) {
    Write-Host "Log file not found at $logPath" -ForegroundColor Red
    exit
}

# Read lines, excluding comment lines
$logLines = Get-Content $logPath | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }

# Define output object list
$logData = @()

foreach ($line in $logLines) {
    $fields = $line -split '\s+'

    if ($fields.Length -ge 13) {
        $entry = [PSCustomObject]@{
            Date       = $fields[0]
            Time       = $fields[1]
            Action     = $fields[2]
            Protocol   = $fields[3]
            SrcIP      = $fields[4]
            DstIP      = $fields[5]
            SrcPort    = $fields[6]
            DstPort    = $fields[7]
            Size       = $fields[8]
            TcpFlags   = $fields[9]
            TcpSyn     = $fields[10]
            TcpAck     = $fields[11]
            Interface  = $fields[12]
        }

        $logData += $entry
    }
}

# Filter (optional): show only dropped packets
$dropOnly = $logData | Where-Object { $_.Action -eq "DROP" }

# Display
$dropOnly | Format-Table -AutoSize

# (Optional) Export to CSV
$dropOnly | Export-Csv "$env:USERPROFILE\Desktop\firewall_dropped_packets.csv" -NoTypeInformation
Write-Host "`nExported to: $env:USERPROFILE\Desktop\firewall_dropped_packets.csv" -ForegroundColor Green
