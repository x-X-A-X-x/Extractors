$Logs = @("System", "Application", "Security", "Setup")

foreach ($Log in $Logs) {
    $ExportCSV = Join-Path $ExportPath "$Log`_Logs.csv"
    ...
    Get-WinEvent -FilterHashtable @{
        LogName = $Log;
        StartTime = $StartTime;
        EndTime = $EndTime
    } | Select-Object TimeCreated, Id, LevelDisplayName, Message |
      Export-Csv -Path $ExportCSV -NoTypeInformation
}
