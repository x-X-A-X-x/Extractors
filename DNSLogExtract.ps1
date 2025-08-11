# Input EVTX and output CSV paths
$evtx = 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-DNS-Client%4Operational.evtx'
$out  = "$env:USERPROFILE\Desktop\dns_client_operational.csv"

Get-WinEvent -Path $evtx |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $kv  = @{}
    foreach ($d in $xml.Event.EventData.Data) { $kv[$d.Name] = [string]$d.'#text' }

    [pscustomobject]@{
      TimeCreated     = $_.TimeCreated
      EventID         = $_.Id
      Level           = $_.LevelDisplayName
      Computer        = $_.MachineName
      Provider        = $_.ProviderName
      # Common DNS fields (present when available)
      QueryName       = $kv['QueryName']
      QueryType       = $kv['QueryType']
      QueryOptions    = $kv['QueryOptions']
      ServerAddress   = $kv['ServerAddress']
      AddressFamily   = $kv['AddressFamily']
      Protocol        = $kv['Protocol']
      ResponseCode    = $kv['ResponseCode']
      # Raw payload as JSON for completeness
      EventDataJson   = ($kv | ConvertTo-Json -Compress)
      Message         = $_.Message
    }
  } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8

Write-Host "Done. CSV -> $out"
