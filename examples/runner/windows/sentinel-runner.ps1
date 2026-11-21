<#
.SYNOPSIS
The Windows runner's entry point: the just-in-time configuration arrives on standard input, as it
does for the Linux image's /usr/local/bin/sentinel-runner (docs/runner-mode.md#the-configuration-is-a-credential).

.DESCRIPTION
Reads at most the bound the worker states (131072 bytes), refuses an empty, oversized or
multi-line configuration without echoing it, and runs the listener beside this script with it.
Exit codes are the Linux entry point's: 2 for a refused configuration, 3 for a missing runner.
#>
$ErrorActionPreference = 'Stop'
$bound = 131072

function Deny([string]$Why, [int]$Code = 2) {
    [Console]::Error.WriteLine("sentinel-runner: $Why")
    exit $Code
}

$listener = Join-Path $PSScriptRoot 'bin\Runner.Listener.exe'
if (-not (Test-Path -LiteralPath $listener -PathType Leaf)) { Deny "no runner at $listener" 3 }
if (-not [Console]::IsInputRedirected) { Deny 'the configuration is read from standard input, not from a terminal' }

$buffer = New-Object char[] ($bound + 3)
$read = 0
while ($read -lt $buffer.Length) {
    $n = [Console]::In.Read($buffer, $read, $buffer.Length - $read)
    if ($n -le 0) { break }
    $read += $n
}
$config = (New-Object string ($buffer, 0, $read)).TrimEnd("`r", "`n")
[Array]::Clear($buffer, 0, $buffer.Length)
if ($config.IndexOfAny([char[]]"`r`n") -ge 0) { Deny 'the input is more than one line' }
if (-not $config) { Deny 'an empty configuration' }
if ($config.Length -gt $bound) { Deny "the configuration is larger than $bound bytes" }

Set-Location -LiteralPath $PSScriptRoot
& $listener run --jitconfig $config
exit $LASTEXITCODE
