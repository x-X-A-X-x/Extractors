# ELExtract_Split.ps1
# Extracts System, Application, Security, and Setup logs into separate CSV files

# Set export folder (same as script location)
$ExportPath = $PSScriptRoot

# Time range: last 7 days
$StartTime = (Get-Date).AddDays(-7)
$EndTime = Get-Date

# List of logs to extract
$Logs = @("System", "Application", "Security", "Setup")

foreach ($Log in $Logs) {
    try {
        Write-Host "`nExtracting $Log log..."

        $ExportCSV = Join-Path $ExportPath "$Log`_Logs.csv"

        Get-WinEvent -FilterHashtable @{
            LogName = $Log;
            StartTime = $StartTime;
            EndTime = $EndTime
        } | Select-Object TimeCreated, Id, LevelDisplayName, Message |
          Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8

        Write-Host "Exported $Log logs to: $ExportCSV"
    }
    catch {
        Write-Host ("Failed to extract {0}: {1}" -f $Log, $_.Exception.Message)
    }
}
