@echo off
set scriptdir=%~dp0

powershell -ExecutionPolicy Bypass -File "%scriptdir%FExtract.ps1"
powershell -ExecutionPolicy Bypass -File "%scriptdir%DNSLogExtractv2.ps1"
powershell -ExecutionPolicy Bypass -File "%scriptdir%ELExtractPrime.ps1"
powershell -ExecutionPolicy Bypass -File "%scriptdir%ELExtractv2.ps1"

pause
