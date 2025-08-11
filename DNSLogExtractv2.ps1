# Extract-DnsClient-Jsonl.ps1
param(
  [string]$Evtx = 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-DNS-Client%4Operational.evtx',
  [string]$Out  = "$env:USERPROFILE\Desktop\dns_client_operational.jsonl",
  [int[]] $EventIds = @(3008,3009,3010)  # query sent/completed/summary
)

# Lookup maps for better analytics
$DnsType = @{
  1='A'; 2='NS'; 5='CNAME'; 6='SOA'; 12='PTR'; 15='MX'; 16='TXT'; 28='AAAA'; 33='SRV'; 255='ANY'
}
$Rcode = @{
  0='NOERROR'; 1='FORMERR'; 2='SERVFAIL'; 3='NXDOMAIN'; 4='NOTIMP'; 5='REFUSED'
}

# Stream -> parse -> write JSON lines
$sw = [System.IO.StreamWriter]::new($Out, $false, [System.Text.UTF8Encoding]::new($true))
try {
  Get-WinEvent -Path $Evtx -Oldest | Where-Object { $EventIds -contains $_.Id } | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $kv  = @{}
    foreach ($d in $xml.Event.EventData.Data) { $kv[$d.Name] = [string]$d.'#text' }

    # Normalize
    $iso   = $_.TimeCreated.ToString('o')                 # ISO8601
    $epoch = [int][Math]::Floor((Get-Date $_.TimeCreated -UFormat %s)) # _time for Splunk

    $qtNum = [int]($kv['QueryType']   | ForEach-Object { $_ })  # safe cast
    $rcNum = [int]($kv['ResponseCode']| ForEach-Object { $_ })

    $rec = [ordered]@{
      # Splunk-friendly metadata
      _time          = $epoch                    # Splunk will use this if props allow, or via HEC
      host           = $_.MachineName
      source         = $Evtx
      sourcetype     = 'msdns:client'            # pick a stable sourcetype

      # Useful headers
      TimeCreated    = $iso
      EventID        = $_.Id
      Provider       = $_.ProviderName
      Level          = $_.LevelDisplayName
      Opcode         = $_.OpcodeDisplayName
      Task           = $_.TaskDisplayName
      ActivityId     = "$($_.ActivityId)"

      # DNS specifics (CIM-ish)
      query          = $kv['QueryName']          # CIM: query
      query_normalized = ($kv['QueryName'] -as [string]).ToLowerInvariant()
      query_type_num = $qtNum
      query_type     = $(if ($DnsType.ContainsKey($qtNum)) { $DnsType[$qtNum] } else { "$qtNum" })
      response_code_num = $rcNum
      response_code  = $(if ($Rcode.ContainsKey($rcNum)) { $Rcode[$rcNum] } else { "$rcNum" })

      # Derive outcome/action for quick stats
      action         = $(if ($rcNum -eq 0) { 'allowed' } elseif ($rcNum -eq 3) { 'nxdomain' } else { 'other' })
      result         = $(if ($rcNum -eq 0) { 'success' } else { 'failure' })

      # Networkish hints (present if log includes them)
      dns_server     = $kv['ServerAddress']
      address_family = $kv['AddressFamily']      # 2=AF_INET, 23=AF_INET6 (if present)
      protocol       = $kv['Protocol']           # e.g., UDP/TCP if present
      query_options  = $kv['QueryOptions']

      # Original payloads for completeness
      eventdata      = $kv
      message        = $_.Message
    }

    $sw.WriteLine(($rec | ConvertTo-Json -Depth 5 -Compress))
  }
}
finally { $sw.Close() }

Write-Host "JSONL written -> $Out"
