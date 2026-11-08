[CmdletBinding()]
param(
    [string]$StateRoot = 'D:\tpaa-run\local-stack',
    [switch]$NoFrontend,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 'run_platform.ps1'
$arguments = @{
    StateRoot = $StateRoot
    NoFrontend = [bool]$NoFrontend
    NoBrowser = [bool]$NoBrowser
}

& $launcher @arguments
