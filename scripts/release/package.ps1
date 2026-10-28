<#
.SYNOPSIS
Build and package the Windows x86_64 Sentinel CLI (docs/releasing.md).

.DESCRIPTION
Runs `cargo build --locked --release -p sentinel` from the checkout this script
is in and writes sentinel-<version>-x86_64-windows-cli.zip into -Out, with one
top directory named like the archive holding bin\sentinel.exe, LICENSE,
THIRD-PARTY-LICENSES.md and BUILD-INFO. Entries use forward slashes and the
commit's timestamp. It does not write SHA256SUMS: copy the archive next to the
Linux packages and run `scripts/release/package.sh assemble` in the same
checkout. -Binary packages an existing sentinel.exe instead of building one.
#>
param(
    [string]$Out,
    [string]$Binary,
    [switch]$AllowDirty
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (& git -C $PSScriptRoot rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0) { throw 'not inside a git checkout' }
Set-Location $root
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
if (-not $Out) { $Out = Join-Path $targetDir 'dist' }

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($arch -ne 'X64') { throw "the Windows CLI is released for x86_64; this host is $arch" }

$dirty = [bool](& git status --porcelain --untracked-files=no)
if ($dirty -and -not $AllowDirty) {
    throw 'the working tree has uncommitted changes; commit them, or pass -AllowDirty for a development package'
}
$version = $null
$inPackage = $false
foreach ($line in Get-Content (Join-Path $root 'Cargo.toml')) {
    if ($line -match '^\[workspace\.package\]') { $inPackage = $true; continue }
    if ($line -match '^\[') { $inPackage = $false }
    if ($inPackage -and $line -match '^version\s*=\s*"(.*)"') { $version = $Matches[1]; break }
}
if (-not $version) { throw 'no workspace version in Cargo.toml' }
$commit = (& git rev-parse HEAD).Trim()
$epoch = [DateTimeOffset]::FromUnixTimeSeconds([long](& git log -1 --format=%ct))

if (-not $Binary) {
    & cargo build --locked --release -p sentinel
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    $Binary = Join-Path $targetDir 'release\sentinel.exe'
}
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "$Binary does not exist" }

$name = "sentinel-$version-x86_64-windows-cli"
$buildInfo = @(
    'package: cli'
    "version: $version"
    "commit: $commit"
    "dirty: $($dirty.ToString().ToLowerInvariant())"
    'arch: x86_64'
    "rustc: $((& rustc --version).Trim())"
) -join "`n"
$entries = [ordered]@{
    "$name/BUILD-INFO"                = [System.Text.Encoding]::UTF8.GetBytes($buildInfo + "`n")
    "$name/LICENSE"                   = [System.IO.File]::ReadAllBytes((Join-Path $root 'LICENSE'))
    "$name/THIRD-PARTY-LICENSES.md"   = [System.IO.File]::ReadAllBytes((Join-Path $root 'THIRD-PARTY-LICENSES.md'))
    "$name/bin/sentinel.exe"          = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Binary))
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$zipPath = Join-Path (Resolve-Path $Out) "$name.zip"
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath }
Add-Type -AssemblyName System.IO.Compression
$stream = [System.IO.File]::Create($zipPath)
try {
    $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($entryName in $entries.Keys) {
            $entry = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $epoch
            $entryStream = $entry.Open()
            try { $entryStream.Write($entries[$entryName], 0, $entries[$entryName].Length) }
            finally { $entryStream.Dispose() }
        }
    }
    finally { $zip.Dispose() }
}
finally { $stream.Dispose() }
Write-Host "packaged $name.zip in $Out"
