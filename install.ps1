# Install Claude Code audit hook (Windows PowerShell).
# Idempotent. Backs up existing settings.json.
$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$ClaudeDir = if ($env:CLAUDE_HOME) { $env:CLAUDE_HOME } else { Join-Path $HOME ".claude" }
$HooksDir  = Join-Path $ClaudeDir "hooks"
$Settings  = Join-Path $ClaudeDir "settings.json"
$HookSrc   = Join-Path $ScriptDir "audit_hook.py"
$HookDest  = Join-Path $HooksDir  "audit_hook.py"
$Merge     = Join-Path $ScriptDir "_merge_settings.py"

$PyBin = $env:PYTHON
if (-not $PyBin) {
    $c = Get-Command python -ErrorAction SilentlyContinue
    if ($c) { $PyBin = $c.Source }
}
if (-not $PyBin) {
    $c = Get-Command py -ErrorAction SilentlyContinue
    if ($c) { $PyBin = $c.Source }
}
if (-not $PyBin) { throw "python not found on PATH (set `$env:PYTHON to override)" }
Write-Host "python: $PyBin"

if (-not (Test-Path $ClaudeDir)) {
    throw "$ClaudeDir not found - install Claude Code first"
}

New-Item -ItemType Directory -Force -Path $HooksDir | Out-Null
Copy-Item -Force $HookSrc $HookDest
Write-Host "installed: $HookDest"

Write-Host "--- self-test ---"
& $PyBin $HookDest
if ($LASTEXITCODE -ne 0) { throw "self-test failed (exit $LASTEXITCODE)" }
Write-Host "-----------------"

if (Test-Path $Settings) {
    $bak = "$Settings.bak-$([DateTimeOffset]::Now.ToUnixTimeSeconds())"
    Copy-Item $Settings $bak
    Write-Host "backup: $bak"
}

$env:PYBIN        = ($PyBin    -replace '\\','/')
$env:HOOK_DEST    = ($HookDest -replace '\\','/')
$env:SETTINGS_PATH = $Settings
& $PyBin $Merge
if ($LASTEXITCODE -ne 0) { throw "merge failed" }

Write-Host ""
Write-Host "DONE. Open a NEW 'claude' session to activate. Smoke-test:"
Write-Host "  1. prompt: token sk-ant-oat01-AbCdEf0123456789xyz  (should BLOCK)"
Write-Host "  2. prompt: email user@example.com  (should mask)"
Write-Host "  3. ask Claude to Read ~/.claude/.credentials.json  (should DENY)"
