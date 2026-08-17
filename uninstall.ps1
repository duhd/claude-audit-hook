$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$ClaudeDir = if ($env:CLAUDE_HOME) { $env:CLAUDE_HOME } else { Join-Path $HOME ".claude" }
$Settings  = Join-Path $ClaudeDir "settings.json"
$Hook      = Join-Path $ClaudeDir "hooks/audit_hook.py"
$Unmerge   = Join-Path $ScriptDir "_unmerge_settings.py"

$PyBin = $env:PYTHON
if (-not $PyBin) { $PyBin = (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $PyBin) { $PyBin = (Get-Command py     -ErrorAction SilentlyContinue).Source }
if (-not $PyBin) { throw "python not found" }

if (Test-Path $Settings) {
    Copy-Item $Settings "$Settings.bak-$([DateTimeOffset]::Now.ToUnixTimeSeconds())"
    $env:SETTINGS_PATH = $Settings
    & $PyBin $Unmerge
}

if (Test-Path $Hook) { Remove-Item $Hook; Write-Host "removed: $Hook" }
Write-Host "DONE. Restart 'claude' session for changes to take effect."
