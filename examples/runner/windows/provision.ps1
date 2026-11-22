<#
.SYNOPSIS
Installs the pinned runner and toolset into a Windows Server 2025 guest image (docs/runner-images.md).

.DESCRIPTION
Reads the windows rows of toolset.tsv, checks every download against the checksum its row states
before unpacking it, and lays the runner under -Root and the toolchains under -ToolCache in the
layout the setup actions resolve from. It writes the runner's own `.env` and `.path` files and
changes nothing else on the machine: no registry key, no machine PATH, no service.

A tool GitHub's hosted image carries and this one does not is answered by a refusal last on the
job's PATH (absent.txt), so a step that calls it fails with the reason in its log.

.EXAMPLE
.\provision.ps1 -Root C:\actions-runner -ToolCache C:\hostedtoolcache\windows
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\actions-runner',
    [string]$ToolCache = 'C:\hostedtoolcache\windows',
    # Default: toolset.tsv one directory up, and absent.txt beside this script.
    [string]$Manifest = '',
    [string]$Absent = '',
    # Tools to install; every windows row by default.
    [string[]]$Only = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Manifest) { $Manifest = Join-Path $here '..\toolset.tsv' }
if (-not $Absent) { $Absent = Join-Path $here 'absent.txt' }
# `-File` hands a comma-separated list over as one string.
$Only = @($Only | ForEach-Object { $_.Split(',') } | Where-Object { $_ })
# The two roots are written into the runner's files, so they are stated in full.
$Root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Root)
$ToolCache = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolCache)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$work = Join-Path ([IO.Path]::GetTempPath()) ("sentinel-provision-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

function Get-Checked([string]$Url, [string]$Sum) {
    $out = Join-Path $work ([IO.Path]::GetFileName(([Uri]$Url).AbsolutePath))
    Invoke-WebRequest -Uri $Url -OutFile $out -UseBasicParsing
    $algorithm = switch ($Sum.Length) { 64 { 'SHA256' } 128 { 'SHA512' } default { throw "a checksum of $($Sum.Length) characters" } }
    $got = (Get-FileHash -Path $out -Algorithm $algorithm).Hash
    if ($got -ne $Sum) { throw "$Url does not match its pinned checksum" }
    $out
}

# Unpacks an archive whose content sits under one top-level directory into $Into itself.
function Expand-Stripped([string]$Zip, [string]$Into) {
    $stage = Join-Path $work ([Guid]::NewGuid().ToString('N'))
    Expand-Archive -Path $Zip -DestinationPath $stage
    $top = @(Get-ChildItem -LiteralPath $stage)
    if ($top.Count -ne 1 -or -not $top[0].PSIsContainer) { throw "$Zip does not hold a single top-level directory" }
    New-Item -ItemType Directory -Force -Path (Split-Path $Into) | Out-Null
    Move-Item -LiteralPath $top[0].FullName -Destination $Into
}

# The layout `@actions/tool-cache` finds: <cache>\<name>\<version>\x64, with a marker beside it.
function Install-Slot([string]$Name, [string]$Version, [string]$Zip) {
    $dir = Join-Path $ToolCache "$Name\$Version\x64"
    if (Test-Path $dir) { throw "$dir already exists" }
    Expand-Stripped $Zip $dir
    New-Item -ItemType File -Path "$dir.complete" | Out-Null
    $dir
}

$environment = [Collections.Generic.List[string]]::new()
$path = [Collections.Generic.List[string]]::new()
$installed = [Collections.Generic.List[string]]::new()
$environment.Add("RUNNER_TOOL_CACHE=$ToolCache")
$environment.Add("AGENT_TOOLSDIRECTORY=$ToolCache")

try {
    New-Item -ItemType Directory -Force -Path $Root, $ToolCache | Out-Null
    $rows = Get-Content -LiteralPath $Manifest | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
        $f = $_.Split("`t")
        [pscustomobject]@{ Tool = $f[0]; Version = $f[1]; Os = $f[2]; Arch = $f[3]; Sum = $f[4]; Url = $f[5] }
    } | Where-Object { $_.Os -eq 'windows' -and $_.Arch -eq 'x64' -and ($Only.Count -eq 0 -or $Only -contains $_.Tool) }
    if (-not $rows) { throw "$Manifest has no windows/x64 rows to install" }

    # Rows are in manifest order, newest version of a tool first: the first one is the job's default.
    $defaulted = @{}
    foreach ($row in $rows) {
        Write-Host "provision: $($row.Tool) $($row.Version)"
        $first = -not $defaulted.ContainsKey($row.Tool)
        $defaulted[$row.Tool] = $true
        switch ($row.Tool) {
            'runner' {
                Expand-Archive -Path (Get-Checked $row.Url $row.Sum) -DestinationPath $Root
            }
            'git' {
                $dir = Join-Path $Root 'externals\mingit'
                Expand-Archive -Path (Get-Checked $row.Url $row.Sum) -DestinationPath $dir
                $path.Add((Join-Path $dir 'cmd'))
            }
            'node' {
                $dir = Install-Slot 'node' $row.Version (Get-Checked $row.Url $row.Sum)
                if ($first) { $path.Add($dir) }
            }
            'go' {
                $dir = Install-Slot 'go' $row.Version (Get-Checked $row.Url $row.Sum)
                $minor = ($row.Version.Split('.')[0..1]) -join '_'
                $environment.Add("GOROOT_${minor}_X64=$dir")
                if ($first) { $path.Add((Join-Path $dir 'bin')) }
            }
            'temurin' {
                $dir = Install-Slot 'Java_Temurin-Hotspot_jdk' $row.Version.Replace('+', '-') (Get-Checked $row.Url $row.Sum)
                $major = $row.Version.Split('.')[0]
                $environment.Add("JAVA_HOME_${major}_X64=$dir")
                # JDK 17 is the default, as on GitHub's image.
                if ($major -eq '17') { $environment.Add("JAVA_HOME=$dir"); $path.Add((Join-Path $dir 'bin')) }
            }
            'maven' {
                $dir = Join-Path $Root 'externals\maven'
                Expand-Stripped (Get-Checked $row.Url $row.Sum) $dir
                $path.Add((Join-Path $dir 'bin'))
            }
            'rust' {
                # The GNU host toolchain links by itself; the MSVC one needs Visual Studio's build
                # tools, which this image does not carry (absent.txt names `cl` and `link`).
                $init = Get-Checked $row.Url $row.Sum
                $env:RUSTUP_HOME = Join-Path $Root 'externals\rustup'
                $env:CARGO_HOME = Join-Path $Root 'externals\cargo'
                & $init -y --no-modify-path --profile minimal --component clippy,rustfmt `
                    --default-host x86_64-pc-windows-gnu --default-toolchain $row.Version
                if ($LASTEXITCODE -ne 0) { throw "rustup-init exited $LASTEXITCODE" }
                $environment.Add("RUSTUP_HOME=$($env:RUSTUP_HOME)")
                $environment.Add("CARGO_HOME=$($env:CARGO_HOME)")
                $path.Add((Join-Path $env:CARGO_HOME 'bin'))
            }
            default { throw "no install for '$($row.Tool)'" }
        }
        $installed.Add("$($row.Tool)`t$($row.Version)")
    }

    # A refusal for every hosted-image command this image leaves out, last on the job's PATH.
    $refusals = Join-Path $Root 'externals\absent'
    New-Item -ItemType Directory -Force -Path $refusals | Out-Null
    $jobPath = ($path + ($env:Path -split ';' | Where-Object { $_ })) -join ';'
    foreach ($tool in Get-Content -LiteralPath $Absent | Where-Object { $_ -and -not $_.StartsWith('#') }) {
        $carried = $path | Where-Object { Test-Path (Join-Path $_ "$tool.exe") -PathType Leaf }
        if ($carried) { throw "absent.txt names '$tool', which this image carries" }
        $message = "::error title=Not in the Sentinel runner image::'$tool' is on GitHub's hosted runner image but not in this image's published subset. Install it in a step, or see docs/runner-images.md."
        Set-Content -LiteralPath (Join-Path $refusals "$tool.cmd") -Encoding Ascii -Value "@echo $message 1>&2", '@exit /b 127'
    }

    # The runner reads these two files beside itself and gives every job their content.
    Set-Content -LiteralPath (Join-Path $Root '.env') -Encoding Ascii -Value $environment
    Set-Content -LiteralPath (Join-Path $Root '.path') -Encoding Ascii -NoNewline -Value "$jobPath;$refusals"
    Set-Content -LiteralPath (Join-Path $Root 'sentinel-toolset.tsv') -Encoding Ascii -Value $installed
    Copy-Item -LiteralPath (Join-Path $here 'sentinel-runner.ps1') -Destination $Root
    Write-Host "provision: $($installed.Count) tools installed under $Root and $ToolCache"
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
