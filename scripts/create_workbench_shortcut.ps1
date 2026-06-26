$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$launcher = Join-Path $scriptDir "start_workbench.cmd"
$desktopPath = [Environment]::GetFolderPath("Desktop")

if (-not $desktopPath) {
    throw "Desktop path could not be resolved."
}

if (-not (Test-Path $launcher)) {
    throw "Launcher not found: $launcher"
}

$shortcutPath = Join-Path $desktopPath "AI Security Workbench.lnk"
if (Test-Path $shortcutPath) {
    Write-Host "Shortcut already exists: $shortcutPath" -ForegroundColor Yellow
    exit 0
}

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $launcher
$shortcut.WorkingDirectory = $projectRoot
$shortcut.IconLocation = "$env:SystemRoot\System32\SHELL32.dll,220"
$shortcut.Save()

Write-Host "Shortcut created: $shortcutPath" -ForegroundColor Green
