# Path to Windows Firewall log file
$logPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

# Read the file and skip comment lines
$lines = Get-Content $logPath | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }

# Process each line into a structured object
$entries = foreach ($line in $lines) {
    $fields = $line -split '\s+'
    if ($fields.Length -ge 13) {
        [PSCustomObject]@{
            date       = $fields[0]
            time       = $fields[1]
            action     = $fields[2]
            protocol   = $fields[3]
            src_ip     = $fields[4]
            dst_ip     = $fields[5]
            src_port   = $fields[6]
            dst_port   = $fields[7]
            size       = $fields[8]
            tcp_flags  = $fields[9]
            tcp_syn    = $fields[10]
            tcp_ack    = $fields[11]
            interface  = $fields[12]
        }
    }
}

# Export to CSV (Splunk/Wazuh compatible)
$entries | Export-Csv "$env:USERPROFILE\Desktop\firewall_for_siem.csv" -NoTypeInformation
Write-Host "Exported to: $env:USERPROFILE\Desktop\firewall_for_siem.csv"
