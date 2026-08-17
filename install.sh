#!/usr/bin/env bash
# Install Claude Code audit hook (macOS / Linux / Windows-git-bash).
# Idempotent. Backs up existing settings.json.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${CLAUDE_HOME:-$HOME/.claude}"
HOOKS_DIR="$CLAUDE_DIR/hooks"
SETTINGS="$CLAUDE_DIR/settings.json"
HOOK_SRC="$SCRIPT_DIR/audit_hook.py"
HOOK_DEST="$HOOKS_DIR/audit_hook.py"
MERGE="$SCRIPT_DIR/_merge_settings.py"

PYBIN="${PYTHON:-}"
if [ -z "$PYBIN" ]; then
    if command -v python3 >/dev/null 2>&1; then
        PYBIN="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        PYBIN="$(command -v python)"
    else
        echo "ERROR: python3 not found on PATH (set \$PYTHON to override)" >&2
        exit 1
    fi
fi
echo "python: $PYBIN"

if [ ! -d "$CLAUDE_DIR" ]; then
    echo "ERROR: $CLAUDE_DIR not found — install Claude Code first" >&2
    exit 1
fi

mkdir -p "$HOOKS_DIR"
cp "$HOOK_SRC" "$HOOK_DEST"
chmod +x "$HOOK_DEST" 2>/dev/null || true
echo "installed: $HOOK_DEST"

echo "--- self-test ---"
"$PYBIN" "$HOOK_DEST"
echo "-----------------"

if [ -f "$SETTINGS" ]; then
    BAK="$SETTINGS.bak-$(date +%s)"
    cp "$SETTINGS" "$BAK"
    echo "backup: $BAK"
fi

export PYBIN HOOK_DEST
export SETTINGS_PATH="$SETTINGS"
"$PYBIN" "$MERGE"

echo
echo "DONE. Open a NEW 'claude' session to activate. Smoke-test:"
echo "  1. prompt: token sk-ant-oat01-AbCdEf0123456789xyz  (should BLOCK)"
echo "  2. prompt: email user@example.com  (should mask)"
echo "  3. ask Claude to Read ~/.claude/.credentials.json  (should DENY)"
