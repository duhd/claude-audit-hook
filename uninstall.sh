#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${CLAUDE_HOME:-$HOME/.claude}"
SETTINGS="$CLAUDE_DIR/settings.json"
HOOK="$CLAUDE_DIR/hooks/audit_hook.py"
UNMERGE="$SCRIPT_DIR/_unmerge_settings.py"

PYBIN="${PYTHON:-$(command -v python3 || command -v python)}"

if [ -f "$SETTINGS" ]; then
    cp "$SETTINGS" "$SETTINGS.bak-$(date +%s)"
    export SETTINGS_PATH="$SETTINGS"
    "$PYBIN" "$UNMERGE"
fi

[ -f "$HOOK" ] && rm -f "$HOOK" && echo "removed: $HOOK"
echo "DONE. Restart 'claude' session for changes to take effect."
