#!/usr/bin/env python3
"""Idempotent merge audit_hook into ~/.claude/settings.json.

env: PYBIN, HOOK_DEST, SETTINGS_PATH
"""
import json
import os
import pathlib
import sys


def main():
    p = pathlib.Path(os.environ["SETTINGS_PATH"])
    if p.exists() and p.stat().st_size > 0:
        s = json.loads(p.read_text(encoding="utf-8"))
    else:
        s = {}
    hooks = s.setdefault("hooks", {})
    cmd = '"{}" "{}"'.format(os.environ["PYBIN"], os.environ["HOOK_DEST"])
    entry = {"type": "command", "command": cmd, "timeout": 10}

    def has_audit(arr, matcher_val):
        for e in arr:
            if e.get("matcher", "") != matcher_val:
                continue
            for h in e.get("hooks", []):
                if "audit_hook.py" in h.get("command", ""):
                    return True
        return False

    ups = hooks.setdefault("UserPromptSubmit", [])
    if not any("audit_hook.py" in h.get("command", "")
               for e in ups for h in e.get("hooks", [])):
        ups.append({"hooks": [entry]})
        print("wired UserPromptSubmit")
    else:
        print("UserPromptSubmit already wired")

    for evt in ("PreToolUse", "PostToolUse"):
        arr = hooks.setdefault(evt, [])
        if not has_audit(arr, ""):
            arr.append({"matcher": "", "hooks": [entry]})
            print("wired " + evt)
        else:
            print(evt + " already wired")

    p.write_text(json.dumps(s, indent=2, ensure_ascii=False), encoding="utf-8")
    print("updated: " + str(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
