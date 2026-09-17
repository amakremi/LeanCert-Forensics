$ErrorActionPreference = "Stop"

$PythonPath = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $PythonPath)) {
    Write-Host "Virtual environment not found. Run:"
    Write-Host ".\scripts\setup_windows.ps1"
    exit 1
}

& $PythonPath -m leancert.cli check-lean
& $PythonPath -m leancert.cli run-experiment traces --fetch --build-traces --repeat 5 --variants standard

Write-Host "Reports: reports\"
Write-Host "Aggregate results: results\"
Write-Host "Figures: results\figures\"
Write-Host "Paper tables: results\paper_tables\"
