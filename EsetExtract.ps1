# Discover ESET event channels
Get-WinEvent -ListLog *ESET* | Select LogName, IsEnabled, RecordCount | Sort LogName

# Example: export recent events from the main ESET channel
$log = 'ESET Security'   # adjust if you see a different ESET channel name
$out = "$env:USERPROFILE\Desktop\ESET_$($log -replace '[^\w-]','_').csv"
Get-WinEvent -LogName $log -MaxEvents 20000 |
  Select TimeCreated, Id, LevelDisplayName, ProviderName, Message |
  Export-Csv -NoTypeInformation -Path $out
