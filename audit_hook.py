#!/usr/bin/env python3
"""Claude Code audit hook — mask PII / block secret / deny cred file reads.

Cross-platform (macOS/Linux/Windows). Python 3.7+, stdlib-only.

Spec: 2026-08-17-claude-code-audit-hooks-spec.md (Option C).
Policy:
  secret rõ ràng  -> BLOCK  (exit 2) + stderr báo dev
  PII (email/phone VN/PAN)  -> MASK im lặng (updatedInput/updatedOutput)
  Read/Edit/Write/Bash chạm file credential -> DENY (PreToolUse exit 2)

ReDoS-safe (spec §6):
  - bounded quantifiers, không '+'/'*' trần
  - EMAIL quét theo cửa sổ ±80 quanh '@'
  - PRIVATE_KEY quét quanh '-----BEGIN'
  - PII mask skip khi text > 128KB (BLOCK/redact vẫn chạy)

Chạy self-test:  python3 audit_hook.py
"""

from __future__ import annotations

import json
import re
import statistics
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

WINDOW = 80
MAX_MASK_BYTES = 128 * 1024

BLOCK_PATTERNS = [
    ("ANTHROPIC_OAUTH", re.compile(r"sk-ant-oat[A-Za-z0-9_\-]{10,200}")),
    ("ANTHROPIC_KEY",   re.compile(r"sk-ant-api[A-Za-z0-9_\-]{10,200}")),
    ("GENERIC_SK",      re.compile(r"sk-[A-Za-z0-9_\-]{20,200}")),
    ("JWT",             re.compile(r"eyJ[A-Za-z0-9_\-]{10,4000}\.[A-Za-z0-9_\-]{10,8000}\.[A-Za-z0-9_\-]{3,2000}")),
]

PRIVATE_KEY_ANCHOR = "-----BEGIN"
PRIVATE_KEY_RX = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")

EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}")
PHONE_RX = re.compile(r"(?<!\d)(?:\+84|0)(?:3|5|7|8|9)\d{8}(?!\d)")
PAN_RX   = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")

CRED_PATH_RX = re.compile(
    r"("
    r"\.credentials\.json"
    r"|(^|[\\/])\.env(\.[A-Za-z0-9_\-]{1,32})?$"
    r"|(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$"
    r"|(^|[\\/])\.aws[\\/]credentials"
    r"|(^|[\\/])\.ssh[\\/]"
    r"|(^|[\\/])kubeconfig(-[A-Za-z0-9_\-.]{1,64})?$"
    r"|\.pem$|\.p12$|\.pfx$|\.key$"
    r")",
    re.IGNORECASE,
)

BASH_READ_RX = re.compile(
    r"\b(cat|type|head|tail|less|more|bat|nl|xxd|hexdump|od|strings|cp|mv|scp|"
    r"rsync|base64|openssl|gpg|source)\b",
    re.IGNORECASE,
)

BASH_CRED_ARG_RX = re.compile(
    r"(?:^|\s|['\"=])"
    r"(?:~|\./|\.\./|/|[A-Za-z]:[\\/])?"
    r"[^\s'\"]{0,200}"
    r"(?:\.credentials\.json|\.env(?:\.[A-Za-z0-9_\-]{1,32})?|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|"
    r"\.aws[\\/]credentials|\.ssh[\\/][^\s'\"]{1,64}|"
    r"kubeconfig(?:-[A-Za-z0-9_\-.]{1,64})?|"
    r"[^\s'\"]{1,64}\.(?:pem|p12|pfx|key))"
    r"(?:$|\s|['\"])",
)


def _windowed_search(text, anchor, rx):
    hits = []
    start = 0
    n = len(text)
    while True:
        i = text.find(anchor, start)
        if i < 0:
            break
        lo = max(0, i - WINDOW)
        hi = min(n, i + WINDOW)
        m = rx.search(text, lo, hi)
        if m:
            hits.append(m.group(0))
        start = i + 1
    return hits


def _windowed_sub(text, anchor, rx, repl):
    n_hit = 0
    out = []
    prev = 0
    n = len(text)
    processed_to = 0
    i = 0
    while True:
        i = text.find(anchor, i)
        if i < 0:
            break
        lo = max(processed_to, i - WINDOW)
        hi = min(n, i + WINDOW)
        if lo > prev:
            out.append(text[prev:lo])
        chunk = text[lo:hi]
        new_chunk, k = rx.subn(repl, chunk)
        out.append(new_chunk)
        n_hit += k
        prev = hi
        processed_to = hi
        i = hi
    if prev < n:
        out.append(text[prev:])
    if not n_hit:
        return text, 0
    return "".join(out), n_hit


def scan_block(text):
    found = [name for name, rx in BLOCK_PATTERNS if rx.search(text)]
    if PRIVATE_KEY_ANCHOR in text and _windowed_search(text, PRIVATE_KEY_ANCHOR, PRIVATE_KEY_RX):
        found.append("PRIVATE_KEY")
    return found


def redact_block(text):
    for name, rx in BLOCK_PATTERNS:
        text = rx.sub("[REDACTED:" + name + "]", text)
    if PRIVATE_KEY_ANCHOR in text:
        text, _ = _windowed_sub(text, PRIVATE_KEY_ANCHOR, PRIVATE_KEY_RX, "[REDACTED:PRIVATE_KEY]")
    return text


def apply_mask(text):
    if len(text) > MAX_MASK_BYTES:
        return text, []
    hits = []
    if "@" in text:
        text, n = _windowed_sub(text, "@", EMAIL_RX, "[MASKED:EMAIL]")
        if n:
            hits.append("EMAILx" + str(n))
    text, n = PHONE_RX.subn("[MASKED:PHONE]", text)
    if n:
        hits.append("PHONEx" + str(n))
    text, n = PAN_RX.subn("[MASKED:PAN]", text)
    if n:
        hits.append("PANx" + str(n))
    return text, hits


def handle_user_prompt_submit(payload):
    text = payload.get("user_input", "") or payload.get("prompt", "") or ""
    found = scan_block(text)
    if found:
        return 2, "", (
            "Prompt bị chặn: phát hiện " + ", ".join(found) + ".\n"
            "Secret không được gửi lên LLM. Kiểm tra nguồn rò "
            "(file .env, credential nằm sai chỗ) rồi gõ lại.\n"
            "LƯU Ý: nội dung prompt đã bị xoá — soạn lại sau khi xử lý.\n"
        )
    masked, hits = apply_mask(text)
    if not hits:
        return 0, "", ""
    out = {"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "updatedInput": masked,
    }}
    return 0, json.dumps(out), ""


def _extract_paths(tool_name, tool_input):
    keys = ("file_path", "notebook_path", "path", "filePath")
    return [str(tool_input[k]) for k in keys if k in tool_input and tool_input[k]]


def handle_pre_tool_use(payload):
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if tool_name in ("Read", "Edit", "Write", "NotebookEdit", "Grep", "Glob"):
        for p in _extract_paths(tool_name, tool_input):
            if CRED_PATH_RX.search(p):
                return 2, "", (
                    "Từ chối " + tool_name + " vào file credential: " + p + "\n"
                    "Chính sách: file credential không được đưa nội dung vào context LLM.\n"
                    "Nếu thực sự cần xử lý, dùng shell ngoài Claude hoặc redact trước.\n"
                )
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        if BASH_READ_RX.search(cmd) and BASH_CRED_ARG_RX.search(cmd):
            return 2, "", (
                "Từ chối Bash: command đọc file credential.\n"
                "cmd: " + cmd[:200] + "\n"
                "Chính sách: file credential không được đưa nội dung vào context LLM.\n"
            )
    return 0, "", ""


def handle_post_tool_use(payload):
    tool_result = payload.get("tool_response")
    if tool_result is None:
        tool_result = payload.get("tool_result")
    if isinstance(tool_result, dict):
        text = json.dumps(tool_result, ensure_ascii=False)
        was_dict = True
    else:
        text = str(tool_result or "")
        was_dict = False
    found = scan_block(text)
    masked, mask_hits = apply_mask(text)
    if found:
        masked = redact_block(masked)
    if not found and not mask_hits:
        return 0, "", ""
    if was_dict:
        try:
            new_result = json.loads(masked)
        except Exception:
            new_result = masked
    else:
        new_result = masked
    out = {"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedOutput": new_result,
    }}
    if found:
        out["systemMessage"] = (
            "Đã redact " + ", ".join(found) + " khỏi kết quả " +
            str(payload.get("tool_name")) + " trước khi vào context. "
            "File nguồn vẫn chứa secret — xử lý riêng."
        )
    return 0, json.dumps(out), ""


HANDLERS = {
    "UserPromptSubmit": handle_user_prompt_submit,
    "PreToolUse": handle_pre_tool_use,
    "PostToolUse": handle_post_tool_use,
}


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    handler = HANDLERS.get(payload.get("hook_event_name"))
    if handler is None:
        return 0
    try:
        code, out, err = handler(payload)
    except Exception as e:
        sys.stderr.write("[audit_hook] internal error: " + repr(e) + "\n")
        return 0
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    return code


# ---------------------------- self-test ----------------------------
def _selftest_cases():
    return [
        ("prompt sạch", "UserPromptSubmit",
         {"user_input": "sửa hàm parse trong main.go"}, 0, None),
        ("prompt OAuth token", "UserPromptSubmit",
         {"user_input": "token sk-ant-oat01-AbCdEf0123456789xyz"}, 2, None),
        ("prompt private key", "UserPromptSubmit",
         {"user_input": "-----BEGIN RSA PRIVATE KEY-----\nMIIE"}, 2, None),
        ("prompt JWT", "UserPromptSubmit",
         {"user_input": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef"}, 2, None),
        ("prompt email + phone", "UserPromptSubmit",
         {"user_input": "liên hệ user@example.com hoặc 0912345678"}, 0, "[MASKED:"),
        ("tool result có key", "PostToolUse",
         {"tool_name": "Read", "tool_result": "API=sk-ant-api03-Zz1234567890abcdefgh"},
         0, "[REDACTED:"),
        ("tool result sạch", "PostToolUse",
         {"tool_name": "Read", "tool_result": "package main"}, 0, None),
        ("PreToolUse Read .credentials.json", "PreToolUse",
         {"tool_name": "Read", "tool_input": {"file_path": "/home/u/.claude/.credentials.json"}}, 2, None),
        ("PreToolUse Read .env", "PreToolUse",
         {"tool_name": "Read", "tool_input": {"file_path": "/repo/.env"}}, 2, None),
        ("PreToolUse Read normal", "PreToolUse",
         {"tool_name": "Read", "tool_input": {"file_path": "/repo/main.go"}}, 0, None),
        ("PreToolUse Bash cat id_rsa", "PreToolUse",
         {"tool_name": "Bash", "tool_input": {"command": "cat ~/.ssh/id_rsa"}}, 2, None),
        ("PreToolUse Bash ls", "PreToolUse",
         {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}, 0, None),
        ("PreToolUse Bash python .py file", "PreToolUse",
         {"tool_name": "Bash", "tool_input": {"command": "python audit_hook.py --check"}}, 0, None),
        ("PreToolUse Bash echo cred string", "PreToolUse",
         {"tool_name": "Bash", "tool_input": {"command": 'echo "path is ~/.ssh/id_rsa here"'}}, 0, None),
        ("PreToolUse Bash cat abs path env", "PreToolUse",
         {"tool_name": "Bash", "tool_input": {"command": "cat /repo/.env.local"}}, 2, None),
        ("PreToolUse Bash cp id_ed25519", "PreToolUse",
         {"tool_name": "Bash", "tool_input": {"command": "cp ~/.ssh/id_ed25519 /tmp/leak"}}, 2, None),
    ]


def selftest():
    cases = _selftest_cases()
    header = "{:<38} | {:>4} | {:>6} | result".format("case", "exit", "expect")
    print(header)
    print("-" * 84)
    ok = True
    for name, event, extra, want_code, want_sub in cases:
        payload = {"hook_event_name": event, "session_id": "s"}
        payload.update(extra)
        code, out, err = HANDLERS[event](payload)
        good = code == want_code and (want_sub is None or want_sub in out)
        if want_sub is None and want_code == 0 and event in ("UserPromptSubmit", "PreToolUse"):
            good = good and out == ""
        ok = ok and good
        tag = "PASS" if good else "FAIL"
        suffix = " | " + (out[:44] if out else err[:44]) if (out or err) else ""
        print("{:<38} | {:>4} | {:>6} | {}{}".format(name, code, want_code, tag, suffix))
    print()
    for kb in (4, 64, 512):
        text = ("nội dung file có @ decorator " + "y" * 900 + " ") * max(1, (kb * 1024) // 930)
        samples = []
        for _ in range(20):
            t0 = time.perf_counter()
            HANDLERS["PostToolUse"]({
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_result": text,
            })
            samples.append((time.perf_counter() - t0) * 1000)
        p50 = statistics.median(samples)
        p95 = sorted(samples)[int(len(samples) * .95)]
        gate = " " if p95 < 50 else " OVER-BUDGET"
        print("latency PostToolUse @{:>4}KB : p50={:7.3f}ms p95={:7.3f}ms{}".format(kb, p50, p95, gate))
    print("\nSELF-TEST: " + ("ALL PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(selftest() if sys.stdin.isatty() else main())
