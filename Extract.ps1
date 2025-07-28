# --- Set Parameters ---
$LogName = "System"
$StartTime = Get-Date "2025-07-21T13:40:52"
$EndTime = Get-Date
$ExportCSV = "/home/sandbox/Desktop/System_Logs.csv"
$ExportEVTX = "/home/sandbox/Desktop/System_Logs.evtx"

# --- Export to CSV ---
Get-WinEvent -FilterHashtable {
    LogName = $LogName;
    StartTime = $StartTime;
    EndTime = $EndTime
} | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv -Path $ExportCSV -NoTypeInformation

# --- Export Raw Logs to EVTX ---
wevtutil epl $LogName $ExportEVTX

# --- Output ---
Write-Host "✅ Logs from '$LogName' exported to:"
Write-Host "   📄 CSV: $ExportCSV"
Write-Host "   📂 EVTX: $ExportEVTX"