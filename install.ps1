# LeakHunterX Agent installer (Windows).
#
#   irm https://download.leakhunterx.com/install.ps1 | iex
#
# Installs per-user (no admin needed), puts lhx-agent on PATH and adds a
# Start Menu shortcut. The .exe carries the LeakHunterX icon already.
$ErrorActionPreference = "Stop"

$Version = if ($env:LHX_VERSION) { $env:LHX_VERSION } else { "v1.0.0" }
$BaseUrl = if ($env:LHX_BASE_URL) {
    $env:LHX_BASE_URL
} else {
    "https://github.com/Omkar443/leakhunterx-agent/releases/download/$Version"
}

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\LeakHunterX"
$Dest = Join-Path $InstallDir "lhx-agent.exe"

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "Downloading lhx-agent $Version..."
Invoke-WebRequest -Uri "$BaseUrl/lhx-agent-windows-x64.exe" -OutFile $Dest -UseBasicParsing

# Put the install dir on the user PATH (idempotent).
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    $NewPath = if ([string]::IsNullOrEmpty($UserPath)) { $InstallDir } else { "$UserPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "Added $InstallDir to your PATH (restart your terminal to pick it up)."
}

# Start Menu shortcut; the icon is taken from the executable's own resource.
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$Shortcut = Join-Path $StartMenu "LeakHunterX Agent.lnk"
try {
    $Shell = New-Object -ComObject WScript.Shell
    $Link = $Shell.CreateShortcut($Shortcut)
    $Link.TargetPath = $Dest
    $Link.Arguments = "pair"
    $Link.WorkingDirectory = $InstallDir
    $Link.IconLocation = "$Dest,0"
    $Link.Description = "LeakHunterX Security Scanning Agent"
    $Link.Save()
} catch {
    Write-Host "Could not create the Start Menu shortcut: $($_.Exception.Message)"
}

Write-Host "LeakHunterX Agent installed to $Dest"
Write-Host "Run: lhx-agent pair"
