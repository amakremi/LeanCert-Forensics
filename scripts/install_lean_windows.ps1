$ErrorActionPreference = "Continue"

function Show-LeanStatus {
    $LeanCommand = Get-Command lean -ErrorAction SilentlyContinue
    $LakeCommand = Get-Command lake -ErrorAction SilentlyContinue
    if ($LeanCommand -and $LakeCommand) {
        Write-Host "Lean and Lake are available."
        & lean --version
        & lake --version
        return $true
    }
    return $false
}

if (Show-LeanStatus) {
    exit 0
}

$WingetCommand = Get-Command winget -ErrorAction SilentlyContinue
if ($WingetCommand) {
    Write-Host "Lean/Lake not found. Attempting installation with winget..."
    & winget install --exact --id Lean.Lean --accept-source-agreements --accept-package-agreements --disable-interactivity
} else {
    Write-Host "winget is not available; automatic Lean installation cannot run."
}

$MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($MachinePath -or $UserPath) {
    $env:Path = "$MachinePath;$UserPath"
}

$ElanBin = Join-Path $env:USERPROFILE ".elan\bin"
if (Test-Path -LiteralPath $ElanBin) {
    if ($env:Path -notlike "*$ElanBin*") {
        $env:Path = "$ElanBin;$env:Path"
    }
}

# Some WinGet versions install Lean successfully without creating command links.
# Discover that package layout and make its bin directory available persistently.
$WinGetPackages = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
if (Test-Path -LiteralPath $WinGetPackages) {
    $LeanExecutable = Get-ChildItem -LiteralPath $WinGetPackages -Recurse -Filter "lean.exe" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*Lean.Lean_*" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($LeanExecutable) {
        $LeanBin = $LeanExecutable.DirectoryName
        if ($env:Path -notlike "*$LeanBin*") {
            $env:Path = "$LeanBin;$env:Path"
        }
        $CurrentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $UserPathEntries = @($CurrentUserPath -split ";" | Where-Object { $_ })
        if ($UserPathEntries -notcontains $LeanBin) {
            [Environment]::SetEnvironmentVariable(
                "Path", (($UserPathEntries + $LeanBin) -join ";"), "User"
            )
            Write-Host "Added the WinGet Lean bin directory to the user PATH: $LeanBin"
        }
    }
}

if (Show-LeanStatus) {
    Write-Host "Lean installation and detection succeeded."
    exit 0
}

Write-Host ""
Write-Host "Lean or Lake is still unavailable."
Write-Host "1. Restart PowerShell and run: lean --version; lake --version"
Write-Host "2. Verify that %USERPROFILE%\.elan\bin is in PATH."
Write-Host "3. If needed, install elan manually from https://github.com/leanprover/elan"
Write-Host "4. Rerun the LeanCert-Forensics experiment."
exit 1
