#!/usr/bin/env python3
import csv, json, os, sys, re
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

CSV_PATH = Path("monitor/tools.csv")
ART = Path("artifacts"); ART.mkdir(exist_ok=True)
ALERTS = ART/"alerts.md"
REPORT = ART/"tools_report.md"
STATUS = ART/"tool_status.json"

def yes(v):
    return str(v).strip().lower() in {"1","true","y","yes"}

def normalize_repo(repo: str):
    if not repo: return (None, None)
    s = repo.strip().rstrip("/")
    s = re.sub(r"\.git$", "", s, flags=re.I)
    if s.lower().startswith(("http://","https://")):
        u = urlparse(s)
        if u.netloc.lower() != "github.com": return (None, None)
        parts=[p for p in u.path.split("/") if p]
        return (parts[0], parts[1]) if len(parts)>=2 else (None, None)
    if s.lower().startswith("github.com/"):
        parts=[p for p in s.split("/") if p]
        return (parts[1], parts[2]) if len(parts)>=3 else (None, None)
    parts=s.split("/")
    return (parts[0], parts[1]) if len(parts)==2 and all(parts) else (None, None)

def gh_get(path):
    url = f"https://api.github.com{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "armor-tool-audit"
    }
    tok = os.getenv("GITHUB_TOKEN") or ""
    if tok: headers["Authorization"] = f"Bearer {tok}"
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=15) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8"))
    except HTTPError as e:
        try:
            body=e.read().decode("utf-8")
            data=json.loads(body) if body else {}
        except Exception:
            data={}
        return e.code, data
    except URLError:
        return 0, {}

def read_tools():
    rows=list(csv.DictReader(open(CSV_PATH, newline='', encoding='utf-8')))
    if not rows: return []
    if "Repo" not in rows[0]:
        for r in rows: r["Repo"]=""
    if "AllowArchived" not in rows[0]:
        for r in rows: r["AllowArchived"]=""
    return rows

def audit():
    rows = read_tools()
    out=[]
    quarantined=[]
    for r in rows:
        name = (r.get("Tool") or "").strip()
        repo = (r.get("Repo") or "").strip()
        allow_arch = yes(r.get("AllowArchived",""))
        status = {
            "tool": name,
            "repo": repo or "-",
            "pinned": r.get("Pinned","-") or "-",
            "latest": "-",
            "reasons": [],
            "quarantine": False
        }
        if not repo:
            status["reasons"].append("no repo configured")
            out.append(status); continue

        owner, rname = normalize_repo(repo)
        if not owner:
            status["reasons"].append("no repo configured or unsupported host")
            out.append(status); continue

        code, meta = gh_get(f"/repos/{owner}/{rname}")
        if code == 200:
            archived = bool(meta.get("archived"))
            disabled = bool(meta.get("disabled"))
            if archived:
                status["reasons"].append("no longer supported (archived)")
                status["quarantine"] = not allow_arch
            if disabled:
                status["reasons"].append("disabled")
                status["quarantine"] = True
            # you can enrich "latest" from releases if you want
        elif code == 404:
            status["reasons"].append("repo not found")
            status["quarantine"] = not allow_arch
        elif code == 403:
            status["reasons"].append("rate limited (GitHub API)")
            status["quarantine"] = False  # don't quarantine on rate limit
        else:
            status["reasons"].append(f"github error {code or 'network'}")
            status["quarantine"] = False

        out.append(status)
        if status["quarantine"]:
            quarantined.append(status)

    # alerts.md
    lines=[]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"# Tool Monitor Alerts — {ts}\n\n")
    lines.append("## Quarantined\n\n")
    if quarantined:
        for q in quarantined:
            reason = q["reasons"][0] if q["reasons"] else "policy"
            lines.append(f"- **{q['tool']}** — {reason}\n")
    else:
        lines.append("(none)\n")
    # Allowed (archived)
    allowed_arch=[s for s in out if ("no longer supported" in " ".join(s["reasons"])) and not s["quarantine"]]
    if allowed_arch:
        lines.append("\n## Allowed (archived)\n\n")
        lines.append("_These tools are upstream-archived but explicitly allowed via `monitor/tools.csv` (AllowArchived=true)._ \n\n")
        for s in allowed_arch:
            lines.append(f"- **{s['tool']}** — no longer supported (archived)\n")
    ALERTS.write_text("".join(lines), encoding="utf-8")

    # tools_report.md
    rep=[]
    rep.append("## Tool status report\n\n")
    rep.append("| Tool | Repo | Pinned | Latest | Reasons | Quarantine |\n")
    rep.append("|---|---|---|---|---|---|\n")
    for s in out:
        rep.append(f"| {s['tool']} | {s['repo']} | {s['pinned']} | {s['latest']} | {'; '.join(s['reasons']) or '-'} | {'YES' if s['quarantine'] else 'no'} |\n")
    REPORT.write_text("".join(rep), encoding="utf-8")

    STATUS.write_text(json.dumps({"generated_at": ts, "items": out}, indent=2), encoding="utf-8")

    if quarantined:
        print("Quarantine detected")
    return 0

if __name__ == "__main__":
    sys.exit(audit())
