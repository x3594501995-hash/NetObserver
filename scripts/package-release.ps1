param(
    [string]$Version = "0.2.8",
    [string]$BuildDirectory = "build/vs"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$releaseDir = Join-Path $root (Join-Path $BuildDirectory "Release")
$distRoot = Join-Path $root "dist"
$packageName = "NetObserver-v$Version-win64"
$stage = Join-Path $distRoot $packageName
$zipPath = Join-Path $distRoot "$packageName.zip"

foreach ($executable in @("NetObserver.exe", "netobserver-cli.exe")) {
    $path = Join-Path $releaseDir $executable
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing Release executable: $path"
    }
}

New-Item -ItemType Directory -Force -Path $distRoot | Out-Null
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path $stage | Out-Null

Copy-Item -LiteralPath (Join-Path $releaseDir "NetObserver.exe") -Destination $stage
Copy-Item -LiteralPath (Join-Path $releaseDir "netobserver-cli.exe") -Destination $stage
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $stage
Copy-Item -LiteralPath (Join-Path $root "LICENSE") -Destination $stage
Copy-Item -LiteralPath (Join-Path $root "THIRD_PARTY_NOTICES.md") -Destination $stage

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -LiteralPath $stage -DestinationPath $zipPath

$hash = Get-FileHash -LiteralPath $zipPath -Algorithm SHA256
$hashPath = Join-Path $distRoot "$packageName.sha256"
"$($hash.Hash.ToLower())  $($hash.Path | Split-Path -Leaf)" |
    Set-Content -LiteralPath $hashPath -Encoding ascii

Write-Host "Package: $zipPath"
Write-Host "SHA256:  $($hash.Hash)"
