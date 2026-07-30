[CmdletBinding()]
param(
    [switch]$Once,
    [ValidateRange(15, 3600)]
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$stateRoot = Join-Path $repoRoot 'analysis\local\windows_s25u_bridge'
$captureRoot = Join-Path $stateRoot 'HUMAN_REVIEW'
$statusPath = Join-Path $stateRoot 'PC_CONNECTION_STATUS.txt'
$logPath = Join-Path $stateRoot 'bridge.log'
$phoneRoot = '/sdcard/ShiningForceKR'

New-Item -ItemType Directory -Force -Path $captureRoot | Out-Null

function Write-BridgeLog {
    param([Parameter(Mandatory)][string]$Message)

    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
}

function Find-Adb {
    $command = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe'),
        'C:\platform-tools\adb.exe',
        'C:\adb\adb.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw 'adb.exe was not found. Check the Android Platform Tools installation.'
}

function Find-Git {
    $command = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $candidates = @(
        'C:\Program Files\Git\cmd\git.exe',
        (Join-Path $env:LOCALAPPDATA 'Programs\Git\cmd\git.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

function Invoke-AdbText {
    param(
        [Parameter(Mandatory)][string]$Adb,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $output = & $Adb @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb command failed: $($Arguments -join ' ')"
    }
    return ($output -join [Environment]::NewLine)
}

function Pull-If-Present {
    param(
        [Parameter(Mandatory)][string]$Adb,
        [Parameter(Mandatory)][string]$RemotePath,
        [Parameter(Mandatory)][string]$LocalPath
    )

    & $Adb shell test -f $RemotePath 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Adb pull $RemotePath $LocalPath 2>&1 | Out-Null
        $pullExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($pullExitCode -ne 0) {
        throw "Failed to copy a phone file: $RemotePath"
    }
    return $true
}

$createdNew = $false
$mutex = [Threading.Mutex]::new($true, 'Local\ShiningForceKRWindowsS25UBridge', [ref]$createdNew)
if (-not $createdNew) {
    exit 0
}

try {
    $adb = Find-Adb
    $git = Find-Git
    & $adb start-server 1>$null 2>$null

    do {
        $now = Get-Date
        try {
            $devicesOutput = Invoke-AdbText -Adb $adb -Arguments @('devices', '-l')
            $deviceLines = @(
                $devicesOutput -split '\r?\n' |
                    Where-Object { $_ -match '\sdevice(\s|$)' }
            )
            if ($deviceLines.Count -ne 1) {
                $state = if ($deviceLines.Count -eq 0) { 'waiting for one authorized device' } else { 'multiple devices detected' }
                @(
                    'Shining Force KR Windows-ADB connection status'
                    "State: $state"
                    "Checked: $($now.ToString('yyyy-MM-dd HH:mm:ss K'))"
                ) | Set-Content -LiteralPath $statusPath -Encoding utf8
                if ($Once) {
                    exit 2
                }
                Start-Sleep -Seconds $IntervalSeconds
                continue
            }

            $serial = ($deviceLines[0] -split '\s+')[0]
            $model = Invoke-AdbText -Adb $adb -Arguments @(
                '-s', $serial, 'shell', 'getprop', 'ro.product.model'
            )

            $phoneStatus = Join-Path $stateRoot 'AUTOPILOT_STATUS.txt'
            $nextStep = Join-Path $stateRoot 'NEXT_STEP.txt'
            [void](Pull-If-Present -Adb $adb `
                -RemotePath "$phoneRoot/reports/AUTOPILOT_STATUS.txt" `
                -LocalPath $phoneStatus)
            [void](Pull-If-Present -Adb $adb `
                -RemotePath "$phoneRoot/reports/NEXT_STEP.txt" `
                -LocalPath $nextStep)

            $reviewFiles = @(
                'README.txt',
                '1_BASELINE.png',
                '2_TEST.png',
                '3_AFTER_ADVANCE.png'
            )
            $pulledReview = @()
            foreach ($name in $reviewFiles) {
                if (Pull-If-Present -Adb $adb `
                    -RemotePath "$phoneRoot/reports/HUMAN_REVIEW/$name" `
                    -LocalPath (Join-Path $captureRoot $name)) {
                    $pulledReview += $name
                }
            }

            $remoteHead = 'not checked'
            if ($null -ne $git) {
                $previousErrorAction = $ErrorActionPreference
                try {
                    $ErrorActionPreference = 'Continue'
                    & $git -C $repoRoot fetch origin main 2>&1 | Out-Null
                    $fetchExitCode = $LASTEXITCODE
                }
                finally {
                    $ErrorActionPreference = $previousErrorAction
                }
                if ($fetchExitCode -eq 0) {
                    $remoteHead = (& $git -C $repoRoot rev-parse origin/main 2>$null)
                }
            }

            @(
                'Shining Force KR Windows-ADB connection status'
                'State: connected and synchronized'
                "Device: $model"
                "Serial: $serial"
                "Review files copied: $($pulledReview -join ', ')"
                "GitHub main: $remoteHead"
                "Checked: $($now.ToString('yyyy-MM-dd HH:mm:ss K'))"
                'Safety: ROMs, generated ROMs, and save files are never copied'
            ) | Set-Content -LiteralPath $statusPath -Encoding utf8
            Write-BridgeLog "connected device=$model review_files=$($pulledReview.Count)"
        }
        catch {
            @(
                'Shining Force KR Windows-ADB connection status'
                'State: error'
                "Details: $($_.Exception.Message)"
                "Checked: $($now.ToString('yyyy-MM-dd HH:mm:ss K'))"
            ) | Set-Content -LiteralPath $statusPath -Encoding utf8
            Write-BridgeLog "error=$($_.Exception.Message)"
            if ($Once) {
                throw
            }
        }

        if (-not $Once) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    } while (-not $Once)
}
finally {
    if ($null -ne $mutex) {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
