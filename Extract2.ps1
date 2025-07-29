# Extract_MultipleLogs.ps1
$StartTime = (Get-Date).AddDays(-7) # Past 7 days
$EndTime = Get-Date
$ExportPath = "$PSScriptRoot"       # Same folder as script

# Define logs to extract
$Logs = @("System", "Application", "Security", "Setup")

foreach ($Log in $Logs) {
    $ExportCSV = Join-Path $ExportPath "$Log`_Logs.csv"

    Write-Host "Extracting $Log logs..."
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = $Log;
            StartTime = $StartTime;
            EndTime = $EndTime
        } | Select-Object TimeCreated, Id, LevelDisplayName, Message | 
        Export-Csv -Path $ExportCSV -NoTypeInformation
        Write-Host "✅ $Log logs exported to $ExportCSV"
    }
    catch {
        Write-Host "⚠ Failed to extract $Log logs: $_"
    }
}
