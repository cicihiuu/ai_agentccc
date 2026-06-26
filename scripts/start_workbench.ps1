param(
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$srcDir = Join-Path $projectRoot "src"
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$requirementsPath = Join-Path $projectRoot "requirements.txt"
$runsDir = Join-Path $projectRoot "runs"
$reportsDir = Join-Path $projectRoot "reports"
$stdoutLogPath = Join-Path $runsDir "workbench.stdout.log"
$stderrLogPath = Join-Path $runsDir "workbench.stderr.log"
$appPort = 8000
$appUrl = "http://127.0.0.1:$appPort/"
$healthUrl = "http://127.0.0.1:$appPort/api/health"

function Write-Info($message) {
    Write-Output "[INFO] $message"
}

function Write-Warn($message) {
    Write-Output "[WARN] $message"
}

function Write-Fail($message) {
    Write-Output "[ERROR] $message"
}

function Resolve-Python {
    if (Test-Path $venvPython) {
        return (Resolve-Path $venvPython).Path
    }
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        return $pythonCommand.Source
    }
    throw "Python not found. Install Python or create .venv under the project root."
}

function Test-PythonDependency($pythonExe) {
    & $pythonExe -c "import fastapi, uvicorn, yaml" 2>$null
    if ($LASTEXITCODE -ne 0) {
        $installHint = ('"{0}" -m pip install -r "{1}"' -f $pythonExe, $requirementsPath)
        throw "Missing runtime dependencies. Run: $installHint"
    }
}

function Ensure-Directory($path) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}

function Get-WorkbenchHealth {
    try {
        return Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
    } catch {
        return $null
    }
}

function Test-WorkbenchReady {
    param(
        [System.Diagnostics.Process]$StartedProcess
    )

    if ($null -ne $StartedProcess -and $StartedProcess.HasExited) {
        return $false
    }

    $health = Get-WorkbenchHealth
    if ($null -eq $health -or $health.ok -ne $true) {
        return $false
    }

    $healthProjectRoot = [string]$health.project_root
    if ([string]::IsNullOrWhiteSpace($healthProjectRoot)) {
        return $true
    }
    try {
        $resolvedHealthRoot = (Resolve-Path $healthProjectRoot -ErrorAction Stop).Path
        $resolvedProjectRoot = (Resolve-Path $projectRoot -ErrorAction Stop).Path
        return $resolvedHealthRoot -eq $resolvedProjectRoot
    } catch {
        return $healthProjectRoot.TrimEnd("\", "/") -eq $projectRoot.TrimEnd("\", "/")
    }
}

function Get-ListeningProcessInfo($port) {
    try {
        $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction Stop | Select-Object -First 1
        if (-not $listener) {
            return $null
        }
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)" -ErrorAction SilentlyContinue
        if (-not $process) {
            return $null
        }
        return $process
    } catch {
        return $null
    }
}

function Test-IsProjectWorkbenchProcess($process) {
    if ($null -eq $process) {
        return $false
    }
    $commandLine = [string]$process.CommandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) {
        return $false
    }
    $normalized = $commandLine.ToLowerInvariant()
    $projectMarker = $projectRoot.ToLowerInvariant()
    return $normalized.Contains("uvicorn") -and $normalized.Contains("ai_security_agent.api.app:app") -and $normalized.Contains($projectMarker)
}

function Stop-ProjectWorkbenchProcess($process) {
    if ($null -eq $process) {
        return
    }
    Write-Warn ("Stopping existing Workbench process on port {0}: PID={1}" -f $appPort, $process.ProcessId)
    Stop-Process -Id $process.ProcessId -Force
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 250
        if (-not (Get-ListeningProcessInfo $appPort)) {
            return
        }
    }
    throw "Timed out waiting for the previous Workbench process to stop."
}

function Get-LaunchUrl {
    $stamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    return ("{0}?v={1}" -f $appUrl, $stamp)
}

function Open-WorkbenchBrowser($url) {
    if ($NoBrowser) {
        Write-Info "Browser opening skipped. Open manually: $url"
        return
    }
    try {
        Start-Process $url | Out-Null
    } catch {
        Write-Warn "Workbench started, but opening the browser failed. Open manually: $url"
    }
}

$pythonExe = Resolve-Python
Write-Info "Using Python: $pythonExe"

Test-PythonDependency $pythonExe
Ensure-Directory $runsDir
Ensure-Directory $reportsDir

$env:PYTHONPATH = $srcDir

$existingProcess = Get-ListeningProcessInfo $appPort
if ($existingProcess) {
    if (Test-IsProjectWorkbenchProcess $existingProcess) {
        Stop-ProjectWorkbenchProcess $existingProcess
    } else {
        $details = "PID=$($existingProcess.ProcessId) Name=$($existingProcess.Name) CommandLine=$($existingProcess.CommandLine)"
        throw "Port $appPort is already occupied by another process. $details"
    }
}

if (Test-Path $stdoutLogPath) {
    Remove-Item $stdoutLogPath -Force
}
if (Test-Path $stderrLogPath) {
    Remove-Item $stderrLogPath -Force
}

Write-Info "Starting Workbench at $appUrl"
$startedProcess = Start-Process `
    -FilePath $pythonExe `
    -ArgumentList @("-m", "uvicorn", "ai_security_agent.api.app:app", "--app-dir", $srcDir, "--host", "127.0.0.1", "--port", "$appPort") `
    -WorkingDirectory $projectRoot `
    -RedirectStandardOutput $stdoutLogPath `
    -RedirectStandardError $stderrLogPath `
    -PassThru

Write-Info ("Workbench process started: PID={0}" -f $startedProcess.Id)
Write-Info "Stdout log: $stdoutLogPath"
Write-Info "Stderr log: $stderrLogPath"

for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 500
    if ($startedProcess.HasExited) {
        break
    }
    if (Test-WorkbenchReady -StartedProcess $startedProcess) {
        $health = Get-WorkbenchHealth
        if ($null -ne $health) {
            $frontendSignature = [string]$health.frontend_signature
            if (-not [string]::IsNullOrWhiteSpace($frontendSignature)) {
                Write-Info ("Workbench frontend signature: {0}" -f $frontendSignature)
            }
        }
        $launchUrl = Get-LaunchUrl
        Write-Info "Workbench started successfully."
        Write-Info "Open: $launchUrl"
        Write-Info "Health: $healthUrl"
        Open-WorkbenchBrowser $launchUrl
        exit 0
    }
}

$manualHint = ('"{0}" -m uvicorn ai_security_agent.api.app:app --app-dir "{1}" --host 127.0.0.1 --port {2}' -f $pythonExe, $srcDir, $appPort)
$stderrTail = ""
if (Test-Path $stderrLogPath) {
    $stderrTail = (Get-Content $stderrLogPath -Tail 20 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
}
if ($startedProcess -and $startedProcess.HasExited) {
    Write-Fail ("Workbench process exited early. PID={0}; ExitCode={1}" -f $startedProcess.Id, $startedProcess.ExitCode)
}
Write-Fail "Workbench startup timed out. Run manually: $manualHint"
if ($stderrTail) {
    Write-Fail "Recent stderr:`n$stderrTail"
}
exit 1
