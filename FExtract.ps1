<# Windows Firewall (W3C) -> NDJSON for Splunk/Wazuh #>

# Log path exactly as in the GUI
$logPathRaw = "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
$logPath    = [Environment]::ExpandEnvironmentVariables($logPathRaw)

if (-not (Test-Path -LiteralPath $logPath)) {
    Write-Error "Firewall log not found: $logPath"
    exit 1
}

# Try to read the file; if access is denied or locked, copy to temp and read the copy
$all = $null
try {
    $all = Get-Content -LiteralPath $logPath -Encoding UTF8 -ErrorAction Stop
}
catch {
    Write-Warning "Direct read failed ($($_.Exception.Message)). Copying to temp and reading the copy…"
    $temp = Join-Path $env:TEMP "pfirewall_copy.log"
    try {
        Copy-Item -LiteralPath $logPath -Destination $temp -Force
        $all = Get-Content -LiteralPath $temp -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Error "Unable to read firewall log even after copying: $($_.Exception.Message)"
        exit 2
    }
}

# Discover the column order from '#Fields:' if present; otherwise fall back to FW 1.5
$headerLine = $all | Where-Object { $_ -match '^\s*#Fields:' } | Select-Object -First 1
if ($headerLine) {
    $rawCols = $headerLine -replace '^\s*#Fields:\s*',''
    $cols    = $rawCols -split '\s+' | Where-Object { $_ }
} else {
    # Default for Windows Firewall 1.5 when logging path/pid is enabled
    $cols = @('date','time','action','protocol','src-ip','dst-ip','src-port','dst-port','size','tcpflags','tcpsyn','tcpack','tcpwin','icmptype','icmpcode','info','path','pid')
    Write-Warning "No '#Fields:' header found. Using default FW 1.5 field list: $($cols -join ',')"
}

# Build name -> index map
$idx = @{}
for ($i=0; $i -lt $cols.Count; $i++) { $idx[$cols[$i]] = $i }

function NF([string]$v) { if ([string]::IsNullOrWhiteSpace($v) -or $v -eq '-') { $null } else { $v } }

# Keep only data lines
$dataLines = $all | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }

# Output file (newline-delimited JSON)
$outFile = Join-Path $env:USERPROFILE "Desktop\firewall_with_process.json"
if (Test-Path $outFile) { Remove-Item $outFile -Force }

foreach ($line in $dataLines) {
    $parts = ($line.TrimStart()) -split '\s+'
    if ($parts.Count -lt $cols.Count) { $parts = $parts + (,@('') * ($cols.Count - $parts.Count)) }

    $get = {
        param($name)
        if ($idx.ContainsKey($name)) { NF $parts[$idx[$name]] } else { $null }
    }

    $date     = & $get 'date'
    $time     = & $get 'time'
    $action   = & $get 'action'
    $protocol = & $get 'protocol'
    $src_ip   = & $get 'src-ip'
    $dst_ip   = & $get 'dst-ip'
    $src_port = & $get 'src-port'
    $dst_port = & $get 'dst-port'
    $size     = & $get 'size'
    $tcpflags = & $get 'tcpflags'
    $tcpsyn   = & $get 'tcpsyn'
    $tcpack   = & $get 'tcpack'
    $tcpwin   = & $get 'tcpwin'
    $icmptype = & $get 'icmptype'
    $icmpcode = & $get 'icmpcode'
    $info     = & $get 'info'   # SEND/RECV
    $image    = & $get 'path'
    $pidStr   = & $get 'pid'

    $pid = if ($pidStr -and ($pidStr -as [int])) { [int]$pidStr } else { $null }
    $procName = "N/A"
    if ($pid) { try { $procName = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch { $procName = "N/A" } }

    $ts = $null
    if ($date -and $time) {
        try {
            $dt = [datetime]::Parse("$date $time")
            $ts = $dt.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
        } catch { $ts = $null }
    }

    $obj = [ordered]@{
        ts            = $ts
        date          = $date
        time          = $time
        action        = $action
        protocol      = $protocol
        src_ip        = $src_ip
        dest_ip       = $dst_ip
        src_port      = $src_port
        dest_port     = $dst_port
        bytes         = $size
        tcp_flags     = $tcpflags
        tcp_syn       = $tcpsyn
        tcp_ack       = $tcpack
        tcp_win       = $tcpwin
        icmp_type     = $icmptype
        icmp_code     = $icmpcode
        direction     = $info
        image_path    = $image
        pid           = $pid
        process_name  = $procName
        host          = $env:COMPUTERNAME
        source        = "WindowsFirewall"
        sourcetype    = "windows:firewall:w3c"
        log_path      = $logPath
    }

    ($obj | ConvertTo-Json -Compress) | Out-File -FilePath $outFile -Encoding UTF8 -Append
}

Write-Host "Wrote NDJSON to: $outFile"
