param(
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$projectRootFull = [System.IO.Path]::GetFullPath($projectRoot).TrimEnd('\', '/')
$separator = [System.IO.Path]::DirectorySeparatorChar

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Get-FullPath {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
}

function Test-UnderProjectRoot {
    param([string]$Path)
    $full = Get-FullPath $Path
    if ($full -eq $projectRootFull) {
        return $false
    }
    return $full.StartsWith($projectRootFull + $separator, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-DependencyPath {
    param([string]$Path)
    $full = Get-FullPath $Path
    foreach ($name in @(".venv", "node_modules", ".idea")) {
        $dependencyRoot = Get-FullPath (Join-Path $projectRootFull $name)
        if ($full -eq $dependencyRoot -or $full.StartsWith($dependencyRoot + $separator, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Add-ExistingTarget {
    param(
        [System.Collections.Generic.List[string]]$Targets,
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not (Test-UnderProjectRoot $resolved)) {
        throw "Refusing to clean path outside project root: $resolved"
    }
    if (Test-DependencyPath $resolved) {
        throw "Refusing to clean dependency or IDE path: $resolved"
    }
    if (-not $Targets.Contains($resolved)) {
        [void]$Targets.Add($resolved)
    }
}

function Test-ChildOfPath {
    param(
        [string]$Path,
        [string]$MaybeParent
    )
    $full = Get-FullPath $Path
    $parent = Get-FullPath $MaybeParent
    return $full.StartsWith($parent + $separator, [System.StringComparison]::OrdinalIgnoreCase)
}

$targets = [System.Collections.Generic.List[string]]::new()

foreach ($relative in @(
    "runs",
    "reports",
    "tmp_sql_tool_artifacts",
    ".cache",
    "_analysis",
    ".pytest_cache"
)) {
    Add-ExistingTarget -Targets $targets -Path (Join-Path $projectRootFull $relative)
}

foreach ($fileName in @("engine_recovered.py", "pycdc.exe")) {
    Add-ExistingTarget -Targets $targets -Path (Join-Path $projectRootFull $fileName)
}

foreach ($pattern in @("_tmp_*.py", "tmp_*.txt")) {
    Get-ChildItem -LiteralPath $projectRootFull -File -Force -Filter $pattern | ForEach-Object {
        Add-ExistingTarget -Targets $targets -Path $_.FullName
    }
}

Get-ChildItem -LiteralPath $projectRootFull -Directory -Recurse -Force -Filter "__pycache__" |
    Where-Object { -not (Test-DependencyPath $_.FullName) } |
    ForEach-Object {
        Add-ExistingTarget -Targets $targets -Path $_.FullName
    }

Get-ChildItem -LiteralPath $projectRootFull -File -Recurse -Force -Filter "*.pyc" |
    Where-Object { -not (Test-DependencyPath $_.FullName) } |
    ForEach-Object {
        Add-ExistingTarget -Targets $targets -Path $_.FullName
    }

$prunedTargets = [System.Collections.Generic.List[string]]::new()
foreach ($target in $targets | Sort-Object Length) {
    $coveredByParent = $false
    foreach ($kept in $prunedTargets) {
        if ((Test-Path -LiteralPath $kept -PathType Container) -and (Test-ChildOfPath -Path $target -MaybeParent $kept)) {
            $coveredByParent = $true
            break
        }
    }
    if (-not $coveredByParent) {
        [void]$prunedTargets.Add($target)
    }
}
$targets = $prunedTargets

if ($targets.Count -eq 0) {
    Write-Info "No generated files found."
    exit 0
}

Write-Info ("Project root: {0}" -f $projectRootFull)
Write-Info ("Generated targets: {0}" -f $targets.Count)

foreach ($target in $targets | Sort-Object) {
    if ($DryRun) {
        Write-Host "[DRY-RUN] $target"
        continue
    }
    Write-Host "[DELETE] $target"
    Remove-Item -LiteralPath $target -Recurse -Force
}

if ($DryRun) {
    Write-Info "Dry run complete. No files were deleted."
} else {
    Write-Info "Generated files cleaned."
}
