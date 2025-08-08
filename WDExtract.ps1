# Export all Defender events in the last 7 days
$StartTime = (Get-Date).AddDays(-7)
$ExportPath = "$env:USERPROFILE\Desktop\DefenderLogs.csv"

Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational";
    StartTime = $StartTime
} | Select-Object TimeCreated, Id, LevelDisplayName, Message |
Export-Csv -Path $ExportPath -NoTypeInformation

Write-Host "Logs exported to $ExportPath"
