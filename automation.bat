@echo off
cd /d "Directory of git folder"

REM 1. Run PowerShell script to extract logs
powershell -ExecutionPolicy Bypass -File "Extract.ps1"

REM 2. Launch Streamlit app
streamlit run "Visualizer.py"
pause
