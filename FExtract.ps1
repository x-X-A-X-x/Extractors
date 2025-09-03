# --- auto-elevate ---
# Do "powershell -ExecutionPolicy Bypass -File .\FExtract.ps1" on powershell to run this too, this is for sec purposes only
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
   [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
  Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
  exit
}

# --- SETTINGS ---
$logPathRaw = "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
$logPath    = [Environment]::ExpandEnvironmentVariables($logPathRaw)
$outFile = Join-Path $PSScriptRoot "firewall_with_process.json"
$RelocateIfDenied = $true

function Read-FwLog {
  param([string]$Path)
  try {
    return Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
  } catch {
    Write-Warning "Direct read failed ($($_.Exception.Message)). Trying backup-mode copy…"
    $temp = Join-Path $env:TEMP "pfirewall_copy.log"
    $srcDir = Split-Path $Path -Parent
    $dstDir = Split-Path $temp -Parent
    $file   = Split-Path $Path -Leaf
    $null = New-Item -ItemType Directory -Path $dstDir -Force -ErrorAction SilentlyContinue
    $roc = Start-Process -FilePath robocopy.exe `
      -ArgumentList "`"$srcDir`" `"$dstDir`" `"$file`" /B /R:0 /W:0 /NFL /NDL /NJH /NJS /NC /NS" `
      -PassThru -NoNewWindow -Wait
    if ($roc.ExitCode -ge 8) { throw "Robocopy failed with code $($roc.ExitCode)" }
    return Get-Content -LiteralPath $temp -Encoding UTF8 -ErrorAction Stop
  }
}

if (-not (Test-Path -LiteralPath $logPath)) {
  Write-Error "Firewall log not found: $logPath"
  exit 1
}

$all = $null
try { $all = Read-FwLog -Path $logPath }
catch {
  if ($RelocateIfDenied) {
    Write-Warning "Relocating firewall log to a readable path…"
    $newDir = "C:\FirewallLogs"
    $newLog = Join-Path $newDir "pfirewall.log"
    New-Item -ItemType Directory -Path $newDir -Force | Out-Null
    icacls $newDir /grant "*S-1-5-32-544:(OI)(CI)(F)" /T | Out-Null
    icacls $newDir /grant "Users:(OI)(CI)(RX)" /T | Out-Null
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogFileName $newLog
    Write-Host "Log path changed. Generate some traffic and re-run after a few seconds."
    exit
  } else {
    Write-Error "Unable to read firewall log: $($_.Exception.Message)"
    exit 2
  }
}

$headerLine = $all | Where-Object { $_ -match '^\s*#Fields:' } | Select-Object -First 1
if ($headerLine) {
  $cols = ($headerLine -replace '^\s*#Fields:\s*','') -split '\s+' | Where-Object { $_ }
} else {
  $cols = @('date','time','action','protocol','src-ip','dst-ip','src-port','dst-port',
            'size','tcpflags','tcpsyn','tcpack','tcpwin','icmptype','icmpcode','info','path','pid')
  Write-Warning "No '#Fields:' header found. Using default FW 1.5 fields."
}

$idx = @{}; for ($i=0; $i -lt $cols.Count; $i++) { $idx[$cols[$i]] = $i }
function NF([string]$v) { if ([string]::IsNullOrWhiteSpace($v) -or $v -eq '-') { $null } else { $v } }

$dataLines = $all | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
if (Test-Path $outFile) { Remove-Item $outFile -Force }

foreach ($line in $dataLines) {
  $parts = ($line.TrimStart()) -split '\s+'
  if ($parts.Count -lt $cols.Count) { $parts = $parts + (,@('') * ($cols.Count - $parts.Count)) }

  $get = { param($n) if ($idx.ContainsKey($n)) { NF $parts[$idx[$n]] } else { $null } }

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
  $info     = & $get 'info'
  $image    = & $get 'path'
  $pidField = & $get 'pid'   # raw field text

  # Use a different variable name to avoid colliding with automatic $PID
  $procId = if ($pidField -and ($pidField -as [int])) { [int]$pidField } else { $null }
  $procName = "N/A"
  if ($procId) { try { $procName = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $procName = "N/A" } }

  $ts = $null
  if ($date -and $time) { try { $ts = ([datetime]::Parse("$date $time")).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz") } catch { } }

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
    pid           = $procId       # JSON field remains "pid"
    process_name  = $procName
    host          = $env:COMPUTERNAME
    source        = "WindowsFirewall"
    sourcetype    = "windows:firewall:w3c"
    log_path      = $logPath
  }

  ($obj | ConvertTo-Json -Compress) | Out-File -FilePath $outFile -Encoding UTF8 -Append
}

Write-Host "Wrote NDJSON to: $outFile"
