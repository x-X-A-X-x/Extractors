# --- Set Parameters ---
$LogName = "System"                   # Change to Application, Security, etc.
$StartTime = (Get-Date).AddDays(-7)   # Logs from the past 7 days
$EndTime = Get-Date
$ExportCSV = "$env:USERPROFILE\Desktop\${LogName}_Logs.csv"
$ExportEVTX = "$env:USERPROFILE\Desktop\${LogName}_Logs.evtx"

# --- Export to CSV ---
Get-WinEvent -FilterHashtable @{
    LogName = $LogName;
    StartTime = $StartTime;
    EndTime = $EndTime
} | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv -Path $ExportCSV -NoTypeInformation

# --- Export Raw Logs to EVTX ---
wevtutil epl $LogName $ExportEVTX

# --- Output ---
Write-Host "Logs from '$LogName' exported to:"
Write-Host "   CSV: $ExportCSV"
Write-Host "   EVTX: $ExportEVTX"
