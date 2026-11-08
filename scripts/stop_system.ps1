[CmdletBinding()]
param(
    [string]$StateRoot = 'D:\tpaa-run\local-stack'
)

$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 'run_platform.ps1'
& $launcher -StateRoot $StateRoot -Stop
