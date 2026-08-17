# claude-audit-hook

Cross-platform audit hook cho Claude Code. Chặn/redact secret, mask PII, deny truy cập file credential.

- **Chính sách**: secret rõ ràng → BLOCK; PII (email/phone/PAN) → MASK; Read/Bash chạm file credential → DENY.
- **Nền tảng**: macOS, Linux, Windows.
- **Yêu cầu**: Python 3.7+, Claude Code đã cài (`~/.claude/` tồn tại).
- **Dependency**: stdlib-only. Không cần pip install.
- **Spec nguồn**: `2026-08-17-claude-code-audit-hooks-spec.md`.

## Cài đặt

### macOS / Linux
```bash
tar xzf claude-audit-hook-1.0.0.tgz
cd claude-audit-hook
bash install.sh
```

### Windows (PowerShell)
```powershell
Expand-Archive claude-audit-hook-1.0.0.zip
cd claude-audit-hook
.\install.ps1
```

### Windows (Git Bash / WSL)
`bash install.sh` — installer detect Python + xử lý path đúng.

Installer làm:
1. Detect `python3` (hoặc `python`/`py`); override qua `$PYTHON` / `$env:PYTHON`
2. Copy `audit_hook.py` → `~/.claude/hooks/`
3. Chạy self-test (16 case + latency benchmark, gate p95<50ms @ 512KB)
4. Backup `~/.claude/settings.json` → `.bak-<epoch>`
5. Merge 3 hook entries (idempotent — chạy lại không duplicate)

**Kích hoạt**: mở session `claude` mới. Session cũ giữ config đã load.

## Verify sau cài

Trong session `claude` mới:

| Test | Input | Expected |
|---|---|---|
| BLOCK secret | prompt `token sk-ant-oat01-AbCdEf0123456789xyz` | Prompt bị xoá, stderr nêu pattern |
| MASK PII | prompt `email user@example.com số 0912345678` | Claude thấy `[MASKED:EMAIL]` + `[MASKED:PHONE]` |
| DENY cred Read | ask Claude đọc `~/.claude/.credentials.json` | Read tool bị deny |
| REDACT output | Claude đọc file có `sk-ant-api*` | Context show `[REDACTED:ANTHROPIC_KEY]` |

Manual self-test bất kỳ lúc nào:
```bash
python3 ~/.claude/hooks/audit_hook.py
```

## Custom / Override

**Thay Python binary**:
```bash
PYTHON=/opt/homebrew/bin/python3 bash install.sh
```

**Thay Claude home**:
```bash
CLAUDE_HOME=/custom/path bash install.sh
```

**Tune ngưỡng**: edit `audit_hook.py` — hằng số ở đầu file:
- `WINDOW = 80` — cửa sổ scan quanh anchor
- `MAX_MASK_BYTES = 128*1024` — text lớn hơn skip PII mask (BLOCK vẫn chạy)
- `BLOCK_PATTERNS`, `MASK_PATTERNS`, `CRED_PATH_RX`, `BASH_READ_RX` — regex

Ràng buộc (spec §6):
- Mọi quantifier **bounded** (`{1,64}`), cấm `+`/`*` trần
- Pattern có anchor rõ (`@`, `-----BEGIN`) dùng windowed scan
- Mỗi pattern mới benchmark @ 512KB, gate p95 < 50ms

## Gỡ cài

### macOS / Linux
```bash
bash uninstall.sh
```

### Windows
```powershell
.\uninstall.ps1
```

Uninstall:
1. Backup `settings.json`
2. Remove audit_hook entries khỏi 3 event (`UserPromptSubmit`/`PreToolUse`/`PostToolUse`), giữ nguyên hook khác
3. Delete `~/.claude/hooks/audit_hook.py`

## Rollback nhanh

```bash
# tìm backup gần nhất
ls -t ~/.claude/settings.json.bak-* | head -1
# restore
cp ~/.claude/settings.json.bak-<epoch> ~/.claude/settings.json
```

## Cấu trúc package

```
claude-audit-hook/
├── audit_hook.py          # hook chính, stdlib-only, cross-platform
├── _merge_settings.py     # helper: merge JSON settings idempotent
├── _unmerge_settings.py   # helper: remove hook entries
├── install.sh             # macOS/Linux/Git-Bash installer
├── install.ps1            # Windows PowerShell installer
├── uninstall.sh
├── uninstall.ps1
├── VERSION
└── README.md
```

## Contract (Claude Code hooks API)

Hook đọc JSON payload trên stdin, output JSON trên stdout, exit code:
- `0` — allow (có/không có `updatedInput`/`updatedOutput`)
- `2` — block (stderr hiển thị cho dev, KHÔNG vào context Claude)

Event handled:
- `UserPromptSubmit` — trước khi prompt vào context
- `PreToolUse` — trước khi tool chạy (chặn được truy cập)
- `PostToolUse` — sau khi tool chạy (chỉ chặn nội dung vào context, tool đã thực thi)

Xem docs Claude Code hooks: https://docs.claude.com/en/docs/claude-code/hooks

## Giới hạn đã biết

- **`PostToolUse` không ngăn được truy cập file** — tool đã chạy, chỉ chặn nội dung vào context Claude. Muốn chặn thật, `PreToolUse` deny theo path (đã có).
- **`UserPromptSubmit` exit 2 xoá prompt** — dev soạn dài mất trắng. Stderr message nêu pattern cụ thể để dev biết fix ở đâu.
- **PII mask skip khi text > 128KB** — trade-off latency, BLOCK/redact secret vẫn chạy trên toàn text.
- **False negative Bash**: shell escaping phức tạp (env var, subshell) có thể ẩn cred path khỏi regex. Đây là defense-in-depth layer, không phải cấm tuyệt đối.

## License

Nội bộ VNPAY / Agentic Framework. Không phân phối public.
