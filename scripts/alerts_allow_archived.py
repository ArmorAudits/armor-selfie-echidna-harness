import csv, re, sys
from pathlib import Path

csv_path = Path("monitor/tools.csv")
alerts = Path("artifacts/alerts.md")
if not alerts.exists():
    sys.exit(0)


def allowed_set():
    try:
        rows = list(csv.DictReader(open(csv_path, newline="", encoding="utf-8")))
    except FileNotFoundError:
        return set()
    s = set()
    for r in rows:
        if str((r.get("AllowArchived") or "")).strip().lower() in {
            "true",
            "1",
            "yes",
            "y",
        }:
            t = (r.get("Tool") or "").strip().lower()
            if t:
                s.add(t)
    return s


allowed = allowed_set()
lines = alerts.read_text(encoding="utf-8").splitlines(True)

# find Quarantined section
start = None
for i, l in enumerate(lines):
    if l.strip().lower().startswith("## quarantined"):
        start = i
        break

if start is None:
    sys.exit(0)

end = len(lines)
for j in range(start + 1, len(lines)):
    if lines[j].startswith("## "):
        end = j
        break

section = lines[start:end]
head = section[0]  # "## Quarantined\n"
bullets = section[1:]


def tool_name_from_bullet(b):
    m = re.search(r"- \*\*(.+?)\*\*", b)
    return m.group(1).strip().lower() if m else ""


keep, moved = [], []
for b in bullets:
    if b.strip().startswith("- "):
        n = tool_name_from_bullet(b)
        (moved if n in allowed else keep).append(b)
    else:
        # non-bullet line inside section (unlikely) keep with the 'keep' group
        keep.append(b)

# rebuild quarantined section
new_section = [head]
new_section += keep if keep else ["(none)\n"]

# build/append allowed section
allowed_section = []
if moved:
    allowed_section.append("\n## Allowed (archived)\n")
    allowed_section.append(
        "_These tools are upstream-archived but explicitly allowed via `monitor/tools.csv` (AllowArchived=true)._ \n\n"
    )
    allowed_section += moved

# write back file
new_lines = lines[:start] + new_section + lines[end:] + allowed_section
alerts.write_text("".join(new_lines), encoding="utf-8")
print(
    f"🔧 moved {len(moved)} item(s) to 'Allowed (archived)'; kept {len(keep)} in 'Quarantined'"
)
