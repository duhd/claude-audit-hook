#!/usr/bin/env python3
"""Remove audit_hook entries from ~/.claude/settings.json.

env: SETTINGS_PATH
"""
import json
import os
import pathlib
import sys


def main():
    p = pathlib.Path(os.environ["SETTINGS_PATH"])
    if not p.exists():
        print("no settings.json")
        return 0
    s = json.loads(p.read_text(encoding="utf-8"))
    h = s.get("hooks", {})
    changed = False
    for evt in ("UserPromptSubmit", "PreToolUse", "PostToolUse"):
        if evt not in h:
            continue
        new_arr = []
        for entry in h[evt]:
            kept = [x for x in entry.get("hooks", [])
                    if "audit_hook.py" not in x.get("command", "")]
            if kept:
                entry["hooks"] = kept
                new_arr.append(entry)
            else:
                changed = True
                print("removed empty {} entry".format(evt))
        if new_arr != h[evt]:
            changed = True
        if new_arr:
            h[evt] = new_arr
        else:
            del h[evt]
            print("removed {} (was empty)".format(evt))
    if changed:
        p.write_text(json.dumps(s, indent=2, ensure_ascii=False), encoding="utf-8")
        print("updated: " + str(p))
    else:
        print("nothing to remove")
    return 0


if __name__ == "__main__":
    sys.exit(main())
