$dest = "C:\Logs"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

wevtutil epl Application "$dest\Application.evtx"
wevtutil epl Security    "$dest\Security.evtx"
wevtutil epl Setup       "$dest\Setup.evtx"
wevtutil epl System      "$dest\System.evtx"