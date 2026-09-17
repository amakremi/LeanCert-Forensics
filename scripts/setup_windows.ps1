$ErrorActionPreference = "Stop"

py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host "Setup completed. Run .\scripts\run_experiment.ps1"
Write-Host "Optional Lean 4 installation: .\scripts\install_lean_windows.ps1"
