[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $GitcExe,

    [Parameter(Mandatory = $true)]
    [string] $GitBackend,

    [string] $Makensis = "makensis.exe"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$packagingDir = Split-Path -Parent $scriptDir
$payloadDir = Join-Path $packagingDir "payload"
$payloadBackend = Join-Path $payloadDir "backend"
$distDir = Join-Path $packagingDir "..\dist"

if (-not (Test-Path -LiteralPath $GitcExe -PathType Leaf)) {
    throw "gitc executable not found: $GitcExe"
}
if (-not (Test-Path -LiteralPath $GitBackend -PathType Container)) {
    throw "Git for Windows backend directory not found: $GitBackend"
}
foreach ($required in @(
    (Join-Path $GitBackend "cmd\git.exe"),
    (Join-Path $GitBackend "mingw64\libexec\git-core"),
    (Join-Path $GitBackend "mingw64\bin"),
    (Join-Path $GitBackend "usr\bin")
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Git for Windows backend is incomplete; missing $required"
    }
}
if (-not (Get-Command $Makensis -ErrorAction SilentlyContinue)) {
    throw "NSIS makensis.exe was not found on PATH"
}

New-Item -ItemType Directory -Force -Path $payloadDir | Out-Null
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
if (Test-Path -LiteralPath $payloadBackend) {
    Remove-Item -LiteralPath $payloadBackend -Recurse -Force
}
Copy-Item -LiteralPath $GitcExe -Destination (Join-Path $payloadDir "gitc.exe") -Force
Copy-Item -LiteralPath $GitBackend -Destination $payloadBackend -Recurse -Force

Push-Location $scriptDir
try {
    & $Makensis "gitc.nsi"
    if ($LASTEXITCODE -ne 0) {
        throw "makensis failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
