# TPAA frontend launcher. Starts Vite frontends only; backend services are operator-managed.
# Usage: .\scripts\run_demo.ps1 [-UserOnly] [-TpOnly] [-NoBrowser]

[CmdletBinding()]
param(
    [switch]$UserOnly,
    [switch]$TpOnly,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$frontend = Join-Path $repo 'apps'

if ($UserOnly -and $TpOnly) { throw 'Choose at most one of -UserOnly or -TpOnly.' }

$apps = if ($UserOnly) { @(@{ Name = 'user-web'; Port = 5173 }) }
        elseif ($TpOnly) { @(@{ Name = 'tp-web'; Port = 5174 }) }
        else { @(@{ Name = 'user-web'; Port = 5173 }, @{ Name = 'tp-web'; Port = 5174 }) }

function Get-PortCommandLine([int]$Port) {
    $conn = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $conn) { return $null }
    return (Get-CimInstance Win32_Process -Filter "ProcessId = $($conn.OwningProcess)" -ErrorAction SilentlyContinue).CommandLine
}

function Test-ExpectedApp($app) {
    $command = Get-PortCommandLine $app.Port
    if ($null -eq $command -or $command -notmatch 'vite') { return $false }

    $path = if ($app.Name -eq 'user-web') { '/src/pages/auth/index.tsx' } else { '/src/pages/review/index.tsx' }
    try {
        $source = (Invoke-WebRequest -Uri "http://127.0.0.1:$($app.Port)$path" -UseBasicParsing -TimeoutSec 2).Content
        if ($app.Name -eq 'user-web') { return $source -match 'initialize' }
        return $source -match 'getReviewQueue' -and $source -notmatch 'DemoApplication'
    } catch { return $false }
}

foreach ($app in $apps) {
    $url = "http://127.0.0.1:$($app.Port)/"
    $running = $false
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
        $running = $response.StatusCode -eq 200
    } catch {
        $running = $false
    }
    if ($running) {
        if (Test-ExpectedApp $app) {
            Write-Host "$($app.Name) already running: $url"
            continue
        }
        throw "$url is already occupied by a different frontend. Stop that process, then rerun this script."
    }
    $npmArgs = @('--workspace', "@tpaa/$($app.Name)", 'run', 'dev', '--', '--host', '127.0.0.1', '--port', "$($app.Port)", '--strictPort')
    $proc = Start-Process -FilePath 'npm.cmd' -ArgumentList $npmArgs -WorkingDirectory $frontend -PassThru -WindowStyle Minimized
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch { }
        if ($proc.HasExited) { break }
    }
    if (-not $ready) { throw "Could not start $($app.Name) on $url. Check whether the port is in use." }
    Write-Host "$($app.Name) ready: $url"
}

if (-not $NoBrowser) {
    foreach ($app in $apps) { Start-Process "http://127.0.0.1:$($app.Port)/" }
}

Write-Host 'Frontends only. Start backend and authentication services separately.'
Write-Host 'Browser login is not available yet. Executor profile is test-adapter; server-held keys are not user-controlled custody.'
