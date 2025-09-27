#!/usr/bin/env python3
import csv, os, sys, json, base64, re
from datetime import datetime, timezone, timedelta
import urllib.request

from urllib.parse import urlparse

def normalize_repo(repo: str):
    # Accepts owner/repo, github.com/owner/repo, or full https://github.com/owner/repo[.git]
    if not repo:
        return (None, None)
    s = repo.strip().rstrip('/')
    s = re.sub(r'\.git$', '', s, flags=re.I)

    # Full URL
    if s.lower().startswith('http://') or s.lower().startswith('https://'):
        u = urlparse(s)
        if u.netloc.lower() != 'github.com':
            return (None, None)
        parts = [p for p in u.path.split('/') if p]
        return (parts[0], parts[1]) if len(parts) >= 2 else (None, None)

    # Prefixed with github.com/
    if s.lower().startswith('github.com/'):
        parts = [p for p in s.split('/') if p]
        return (parts[1], parts[2]) if len(parts) >= 3 else (None, None)

    # owner/repo
    parts = s.split('/')
    return (parts[0], parts[1]) if len(parts) == 2 and all(parts) else (None, None)


CSV_PATH = "monitor/tools.csv"
ALERTS_MD = "artifacts/alerts.md"          # will be enriched/rebuilt by this script
REPORT_MD = "artifacts/tools_report.md"    # full table of tool statuses
STATE_JSON = "artifacts/tool_status.json"  # machine-readable summary

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
HEADERS = {"Accept": "application/vnd.github+json"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

def gh_get(url, accept=None):
    req = urllib.request.Request(url, headers=HEADERS if not accept else {**HEADERS, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except Exception:
        return None

def semver_tuple(v):
    if not v: return (0,0,0, "")
    v = v.strip().lstrip("vV")
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", v) or re.match(r"^(\d+)\.(\d+)(.*)$", v)
    if not m: return (0,0,0, v)
    if len(m.groups())==4:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4))
    # x.y -> treat as x.y.0
    return (int(m.group(1)), int(m.group(2)), 0, m.group(3))

def newer(a,b):
    return semver_tuple(a) > semver_tuple(b)

def read_tools(csv_path):
    with open(csv_path, newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    # normalize columns
    for r in rows:
        for k in ("AllowArchived","PinnedVersion","Version","Repo","Tool"):
            r.setdefault(k, "")
    return rows

def detect_deprecated_text(owner, repo):
    rd = gh_get(f"https://api.github.com/repos/{owner}/{repo}/readme")
    if not rd or "content" not in rd: return False
    try:
        text = base64.b64decode(rd["content"]).decode("utf-8", errors="ignore")
        return bool(re.search(r"\bdeprecated\b|\barchived\b|\bunmaintained\b", text, re.I))
    except Exception:
        return False

def latest_release_tag(owner, repo):
    rel = gh_get(f"https://api.github.com/repos/{owner}/{repo}/releases/latest")
    if rel and "tag_name" in rel:
        return rel["tag_name"]
    tags = gh_get(f"https://api.github.com/repos/{owner}/{repo}/tags?per_page=1")
    if tags and isinstance(tags, list) and tags:
        return tags[0].get("name","")
    return ""

def audit_tool(row):
    name = (row.get("Tool") or "").strip()
    repo = (row.get("Repo") or "").strip()
    allow_archived = (row.get("AllowArchived") or "").strip().lower() in ("1","true","yes","y")
    pinned = (row.get("PinnedVersion") or row.get("Version") or "").strip()

    status = {
        "tool": name,
        "repo": repo,
        "allow_archived": allow_archived,
        "pinned": pinned,
        "reasons": [],      # human readable
        "quarantine": False # default until we see cause
    }

    if not repo or "/" not in repo:
        status["reasons"].append("no repo configured")
        return status

    owner, rname = repo.split("/",1)
    meta = gh_get(f"https://api.github.com/repos/{owner}/{rname}")
    if not meta or "full_name" not in meta:
        status["reasons"].append("repo not found")
        status["quarantine"] = True
        return status

    is_archived = bool(meta.get("archived"))
    pushed_at = meta.get("pushed_at")
    last_push = None
    if pushed_at:
        try:
            last_push = datetime.fromisoformat(pushed_at.replace("Z","+00:00"))
        except Exception:
            last_push = None

    # reason: archived
    if is_archived:
        status["reasons"].append("no longer supported")
        status["quarantine"] = not allow_archived

    # reason: deprecated in README
    if detect_deprecated_text(owner, rname):
        status["reasons"].append("no longer supported")
        status["quarantine"] = status["quarantine"] or (not allow_archived)

    # reason: stale > 24 months
    if last_push:
        if datetime.now(timezone.utc) - last_push > timedelta(days=730):
            status["reasons"].append("no longer supported")
            status["quarantine"] = status["quarantine"] or (not allow_archived)

    # reason: needs update (non-quarantine)
    latest = latest_release_tag(owner, rname)
    status["latest"] = latest
    if latest and pinned:
        try:
            if newer(latest, pinned):
                status["reasons"].append("needs update")
        except Exception:
            pass
    elif latest and not pinned:
        # We don’t know installed version; still signal an update exists
        status["reasons"].append("update available")

    # de-duplicate reasons (keep stable order)
    seen = set()
    status["reasons"] = [r for r in status["reasons"] if not (r in seen or seen.add(r))]

    return status

def write_reports(statuses):
    # Rebuild alerts.md with reasons and Allowed section
    quarantined = [s for s in statuses if s["quarantine"]]
    allowed_arch = [s for s in statuses if (not s["quarantine"]) and s["allow_archived"] and ("no longer supported" in s["reasons"])]

    lines = []
    lines.append(f"# Tool Monitor Alerts — {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}\n\n")

    lines.append("## Quarantined\n\n")
    if quarantined:
        for s in sorted(quarantined, key=lambda x: x["tool"].lower()):
            reason = (", ".join(s["reasons"])) or "unknown"
            lines.append(f"- **{s['tool']}** — {reason}\n")
    else:
        lines.append("(none)\n")
    lines.append("\n")

    if allowed_arch:
        lines.append("## Allowed (archived)\n\n")
        lines.append("_These tools are upstream-archived but explicitly allowed via `monitor/tools.csv` (AllowArchived=true)._ \n\n")
        for s in sorted(allowed_arch, key=lambda x: x["tool"].lower()):
            reason = (", ".join(s["reasons"])) or "no longer supported"
            lines.append(f"- **{s['tool']}** — {reason}\n")
        lines.append("\n")

    with open(ALERTS_MD, "w", encoding="utf-8") as f:
        f.write("".join(lines))

    # Table report
    def row(s):
        repo = s["repo"] or "-"
        pinned = s.get("pinned") or "-"
        latest = s.get("latest") or "-"
        reasons = ", ".join(s["reasons"]) or "-"
        q = "YES" if s["quarantine"] else "no"
        return f"| {s['tool']} | {repo} | {pinned} | {latest} | {reasons} | {q} |"

    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("## Tool status report\n\n")
        f.write("| Tool | Repo | Pinned | Latest | Reasons | Quarantine |\n")
        f.write("|---|---|---|---|---|---|\n")
        for s in sorted(statuses, key=lambda x: x["tool"].lower()):
            f.write(row(s) + "\n")

    with open(STATE_JSON, "w", encoding="utf-8") as f:
        json.dump(statuses, f, indent=2)

def main():
    tools = read_tools(CSV_PATH)
    statuses = [audit_tool(r) for r in tools if (r.get("Tool") or "").strip()]
    write_reports(statuses)
    # non-zero exit if any quarantined -> lets CI go red if desired
    if any(s["quarantine"] for s in statuses):
        print("Quarantine detected", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
