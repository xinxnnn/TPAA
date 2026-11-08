# TPAA local port launcher. Services start only when this script is run.
# Usage: .\scripts\run_platform.ps1 [-StateRoot <path>] [-NoFrontend] [-NoBrowser]

[CmdletBinding()]
param(
    [string]$StateRoot = 'D:\tpaa-run\local-stack',
    [switch]$NoFrontend,
    [switch]$NoBrowser,
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$apps = Join-Path $repo 'apps'
if ($StateRoot -notmatch '^[A-Za-z]:[\\/]') { throw "StateRoot must be an absolute Windows drive path: $StateRoot" }
$drive = $StateRoot.Substring(0, 1)
if (-not (Test-Path "$drive`:")) { throw "StateRoot drive '$drive`:' does not exist. Choose an existing drive, such as D:\\tpaa-run\\local-stack." }
$StateRoot = [System.IO.Path]::GetFullPath($StateRoot)
$logRoot = Join-Path $StateRoot 'logs'
if (-not $Stop) { New-Item -ItemType Directory -Force -Path $logRoot | Out-Null }

# TP and AP are logical services in one process; avoid listing the shared process twice.
$services = @(
    @{ Name = 'Executor'; Kind = 'python'; Module = 'services.user_side.executor_service.app:app'; Port = 8110; Health = '/healthz'; WorkDir = $repo },
    @{ Name = 'TP/AP Stack'; Kind = 'python'; Module = 'services.local_test_stack:app'; Port = 8120; Health = '/healthz'; WorkDir = $repo },
    @{ Name = 'Portal'; Kind = 'python'; Module = 'services.user_side.portal_api.app:app'; Port = 8000; Health = '/healthz'; WorkDir = $repo },
    @{ Name = 'User'; Kind = 'frontend'; Module = '@tpaa/user-web'; Port = 5173; Health = '/'; WorkDir = $apps },
    @{ Name = 'TP Reviewer'; Kind = 'frontend'; Module = '@tpaa/tp-web'; Port = 5180; Health = '/'; WorkDir = $apps }
)

function Test-Endpoint([string]$Url) {
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 400
    } catch { return $false }
}

function Get-LogName([string]$Name) {
    return $Name -replace '[^A-Za-z0-9._-]', '-'
}

function Wait-Endpoint([string]$Url, [string]$Name, [int]$TimeoutSeconds = 60,
                      [System.Diagnostics.Process]$Process = $null) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Endpoint $Url) { return }
        if ($null -ne $Process -and $Process.HasExited) {
            $logName = Get-LogName $Name
            foreach ($suffix in @('err', 'out')) {
                $log = Join-Path $logRoot "$logName.$suffix.log"
                if (Test-Path $log) {
                    Write-Host "--- $log ---"
                    Get-Content $log -Tail 40
                }
            }
            throw "$Name process exited with code $($Process.ExitCode) before becoming ready."
        }
        Start-Sleep -Milliseconds 500
    }
    $logName = Get-LogName $Name
    foreach ($suffix in @('err', 'out')) {
        $log = Join-Path $logRoot "$logName.$suffix.log"
        if (Test-Path $log) {
            Write-Host "--- $log ---"
            Get-Content $log -Tail 40
        }
    }
    throw "$Name did not become ready within $TimeoutSeconds seconds at $Url. See $logRoot."
}

function Start-PythonService($service) {
    $logName = Get-LogName $service.Name
    $out = Join-Path $logRoot "$logName.out.log"
    $err = Join-Path $logRoot "$logName.err.log"
    $args = @('-m', 'uvicorn', $service.Module, '--host', '127.0.0.1',
              '--port', "$($service.Port)", '--workers', '1')
    return Start-Process -FilePath 'python' -ArgumentList $args -WorkingDirectory $service.WorkDir `
        -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Minimized -PassThru
}

function Start-Frontend($service) {
    $logName = Get-LogName $service.Name
    $out = Join-Path $logRoot "$logName.out.log"
    $err = Join-Path $logRoot "$logName.err.log"
    $args = @('--workspace', $service.Module, 'run', 'dev', '--', '--host',
              '127.0.0.1', '--port', "$($service.Port)", '--strictPort')
    Start-Process -FilePath 'npm.cmd' -ArgumentList $args -WorkingDirectory $service.WorkDir `
        -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Minimized | Out-Null
}

function Start-Service($service) {
    $url = "http://127.0.0.1:$($service.Port)$($service.Health)"
    if (Test-Endpoint $url) {
        Write-Host "$($service.Name) already ready: $url"
        return
    }
    if ($service.Kind -eq 'route') {
        $owner = $services | Where-Object { $_.Name -eq 'TP' }
        if (-not (Test-Endpoint "http://127.0.0.1:$($owner.Port)/healthz")) {
            throw "Cannot expose $($service.Name): TP stack is not running on $($owner.Port)."
        }
        throw "$($service.Name) health route is not available at $url. Check the TP/AP stack."
    }
    $process = $null
    if ($service.Kind -eq 'python') { $process = Start-PythonService $service }
    elseif ($service.Kind -eq 'frontend') { Start-Frontend $service }
    $timeoutSeconds = if ($service.Kind -eq 'python') { 120 } else { 60 }
    Wait-Endpoint $url $service.Name $timeoutSeconds $process
    Write-Host "$($service.Name) ready: $url"
}

function Stop-PlatformService($service) {
    if ($service.Name -eq 'TP/AP Stack') {
        $ports = @(8120)
    } else {
        $ports = @($service.Port)
    }
    $connections = @($ports | ForEach-Object {
        Get-NetTCPConnection -State Listen -LocalPort $_ -ErrorAction SilentlyContinue
    })
    if ($connections.Count -eq 0) {
        Write-Host "$($service.Name) is not listening on $($service.Port)."
        return
    }
    $pids = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
    foreach ($processId in $pids) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
        if ($null -eq $process) { continue }
        try {
            # -Stop explicitly targets the platform's reserved local ports.
            Stop-Process -Id $processId -Force -ErrorAction Stop
            Write-Host "Stopped listener for $($service.Name) (PID $processId) on port $($service.Port)."
        } catch {
            Write-Warning "Could not stop listener for $($service.Name) PID $processId`: $($_.Exception.Message)"
        }
    }
}

if ($Stop) {
    $stopNames = @('TP Reviewer', 'User', 'Portal', 'TP/AP Stack', 'Executor')
    $remaining = @()
    foreach ($name in $stopNames) {
        $serviceConfig = $services | Where-Object { $_.Name -eq $name }
        if ($null -ne $serviceConfig) { Stop-PlatformService $serviceConfig }
    }
    foreach ($service in $services) {
        $connections = @(Get-NetTCPConnection -State Listen -LocalPort $service.Port -ErrorAction SilentlyContinue)
        if ($connections.Count -gt 0) { $remaining += "$($service.Name):$($service.Port)" }
    }
    if ($remaining.Count -gt 0) {
        Write-Warning "Some listeners remain: $($remaining -join ', '). They were not confirmed as launcher-owned; close them from their original terminal or inspect their PIDs."
    } else {
        Write-Host "All platform ports are closed. Persistent test state remains at $StateRoot."
    }
    return
}

# Provision stable test-only files and load them into this process environment.
& python (Join-Path $repo 'scripts/prepare_local_test.py') '--state-root' $StateRoot
if ($LASTEXITCODE -ne 0) { throw 'Failed to prepare local test-adapter files.' }
$configPath = Join-Path $StateRoot 'local-config.json'
$config = Get-Content $configPath -Raw | ConvertFrom-Json
$config.psobject.Properties | ForEach-Object {
    Set-Item -Path "Env:$($_.Name)" -Value $_.Value
}
$env:PYTHONPATH = $repo
$env:TPAA_EXECUTOR_STATE_ROOT = Join-Path $StateRoot 'executor'
$env:TPAA_EXECUTOR_BIND = '127.0.0.1'
$env:TPAA_EXECUTOR_URL = 'http://127.0.0.1:8110'
$env:TPAA_LOCAL_TEST_STACK = '1'
$env:TPAA_LOCAL_TEST_STACK_URL = 'http://127.0.0.1:8120'
$env:TPAA_USER_STATE_ROOT = Join-Path $StateRoot 'user'
$env:TPAA_USER_WORKFLOW_DB = Join-Path $StateRoot 'user\workflow.json'
$env:TPAA_USER_UPSTREAM = 'http://127.0.0.1:8000'
$env:TPAA_USER_AUTH_HSM_SEED = Join-Path $StateRoot 'user-auth-seed.json'
$env:TPAA_LOCAL_TEST_AUTH = '1'
$env:TPAA_LOCAL_BROWSER_ORIGIN = 'http://127.0.0.1:5173'
$env:TPAA_LOCAL_REVIEWER_AUTH = '1'
$env:TPAA_LOCAL_REVIEWER_ORIGIN = 'http://127.0.0.1:5180'
$env:TPAA_LOCAL_SUPERVISOR_AUTH = '1'
$env:TPAA_LOCAL_SUPERVISOR_ORIGIN = 'http://127.0.0.1:5180'
$env:TPAA_TP_UPSTREAM = 'http://127.0.0.1:8120'

# New executor token is persisted for this Windows user, never printed.
if ([string]::IsNullOrWhiteSpace($env:TPAA_EXECUTOR_TOKEN)) {
    $env:TPAA_EXECUTOR_TOKEN = [Environment]::GetEnvironmentVariable('TPAA_EXECUTOR_TOKEN', 'User')
}
if ([string]::IsNullOrWhiteSpace($env:TPAA_EXECUTOR_TOKEN) -and
    -not (Test-Endpoint 'http://127.0.0.1:8110/healthz')) {
    $env:TPAA_EXECUTOR_TOKEN = [guid]::NewGuid().ToString('N')
    [Environment]::SetEnvironmentVariable('TPAA_EXECUTOR_TOKEN', $env:TPAA_EXECUTOR_TOKEN, 'User')
}
if ([string]::IsNullOrWhiteSpace($env:TPAA_EXECUTOR_TOKEN)) {
    throw 'Executor already listens on 8110. Open a new shell or provide the same TPAA_EXECUTOR_TOKEN.'
}

$executor = $services | Where-Object { $_.Name -eq 'Executor' }
Start-Service $executor
$headers = @{ Authorization = "Bearer $env:TPAA_EXECUTOR_TOKEN" }
try {
    $executorInfo = Invoke-RestMethod -Uri 'http://127.0.0.1:8110/v1/executor/public-key' -Headers $headers
} catch {
    throw 'Executor rejected its configured token. Ensure this is the same token used to start it.'
}
if ([string]::IsNullOrWhiteSpace($executorInfo.owner)) { throw 'Executor did not return an owner.' }
$env:TPAA_EXECUTOR_OWNER = $executorInfo.owner

$stack = $services | Where-Object { $_.Name -eq 'TP/AP Stack' }
Start-Service $stack
$portal = $services | Where-Object { $_.Name -eq 'Portal' }
Start-Service $portal

if (-not $NoFrontend) {
    $user = $services | Where-Object { $_.Name -eq 'User' }
    Start-Service $user
    $tpReviewer = $services | Where-Object { $_.Name -eq 'TP Reviewer' }
    Start-Service $tpReviewer
    if (-not $NoBrowser) { Start-Process 'http://127.0.0.1:5173/' }
    if (-not $NoBrowser) { Start-Process 'http://127.0.0.1:5180/' }
}

Write-Host ''
Write-Host 'TPAA local test-adapter ports:'
$services | ForEach-Object {
    Write-Host ("  {0,-9} http://127.0.0.1:{1}{2}" -f $_.Name, $_.Port, $_.Health)
}
Write-Host 'TP/AP/review/PHC share one local test-adapter process because review and PHC use process-local ports.'
Write-Host 'All services are local test-adapter only; browser sessions use synthetic identities/test STAFF keys, not real user or reviewer authentication.'
