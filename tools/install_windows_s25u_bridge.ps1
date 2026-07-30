[CmdletBinding()]
param(
    [switch]$DoNotStart
)

$ErrorActionPreference = 'Stop'
$bridgePath = Join-Path $PSScriptRoot 'windows_s25u_bridge.ps1'
if (-not (Test-Path -LiteralPath $bridgePath -PathType Leaf)) {
    throw "The connection automation script is missing: $bridgePath"
}

$powerShell = Join-Path $PSHOME 'powershell.exe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$valueName = 'ShiningForceKR-S25U-Bridge'
$quotedBridge = '"{0}"' -f $bridgePath
$command = '"{0}" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File {1}' -f `
    $powerShell, $quotedBridge

New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name $valueName -Value $command `
    -PropertyType String -Force | Out-Null

if (-not $DoNotStart) {
    Start-Process -FilePath $powerShell -WindowStyle Hidden -ArgumentList @(
        '-NoProfile',
        '-WindowStyle', 'Hidden',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $bridgePath)
    )
}

Write-Output 'Windows sign-in auto-start registration completed'
Write-Output "Registration name: $valueName"
Write-Output "Script: $bridgePath"
