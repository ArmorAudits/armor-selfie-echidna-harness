import csv

# --- begin tolerant DictWriter patch ---
import csv as _csv_patch_ref
import datetime
import json
import os
import pathlib
import re
import sys

_OrigDictWriter = _csv_patch_ref.DictWriter


class _FilteringDictWriter(_OrigDictWriter):
    def writerow(self, rowdict):
        # Ignore keys not present in fieldnames, fill missing with ""
        filtered = {k: rowdict.get(k, "") for k in self.fieldnames}
        return super().writerow(filtered)

    def writerows(self, rowdicts):
        for r in rowdicts:
            self.writerow(r)


_csv_patch_ref.DictWriter = _FilteringDictWriter
# --- end tolerant DictWriter patch ---

from typing import Any, Dict, List

import requests
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
ART.mkdir(exist_ok=True, parents=True)

POLICY_MAX_DAYS = int(os.getenv("POLICY_MAX_DAYS_SINCE_RELEASE", "365"))
POLICY_MIN_SEV = os.getenv("POLICY_MIN_SEVERITY_FOR_QUARANTINE", "HIGH").upper()
SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def now_iso() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    )


def read_inventory() -> List[Dict[str, Any]]:
    csv_path = ROOT / "monitor" / "tools.csv"
    yml_path = ROOT / "monitor" / "tools.yaml"
    rows: List[Dict[str, Any]] = []
    if csv_path.exists():
        with open(csv_path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append(r)
        return rows
    if yml_path.exists():
        data = yaml.safe_load(open(yml_path, encoding="utf-8"))
        for t in data.get("tools", []):
            rows.append(
                {
                    "Tool": t.get("tool", ""),
                    "Category": t.get("category", ""),
                    "Chain": t.get("chain", ""),
                    "Vendor": t.get("vendor", ""),
                    "License": t.get("license", ""),
                    "RepoURL": t.get("repo_url", ""),
                    "MonitorMethod": t.get("monitor", ""),
                    "InstallMethod": t.get("install", ""),
                    "BinaryPath": t.get("binary", ""),
                    "Owner": t.get("owner", ""),
                    "Notes": t.get("notes", ""),
                }
            )
        return rows
    print("No monitor/tools.csv or monitor/tools.yaml found", file=sys.stderr)
    return []


def gh_latest_release(repo_url: str, token: str) -> Dict[str, Any]:
    """
    Query GitHub for latest release (fallback to tags if none).
    """
    out = {"latest_tag": None, "published_at": None, "archived": False, "repo": None}
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", repo_url or "")
    if not m:
        return out
    owner, repo = m.group(1), m.group(2)
    out["repo"] = f"{owner}/{repo}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    s = requests.Session()

    # repo meta (archived?)
    r = s.get(
        f"https://api.github.com/repos/{owner}/{repo}", headers=headers, timeout=15
    )
    if r.ok:
        j = r.json()
        out["archived"] = bool(j.get("archived"))
    # releases
    r = s.get(
        f"https://api.github.com/repos/{owner}/{repo}/releases/latest",
        headers=headers,
        timeout=15,
    )
    if r.status_code == 404:
        # try tags
        r2 = s.get(
            f"https://api.github.com/repos/{owner}/{repo}/tags?per_page=1",
            headers=headers,
            timeout=15,
        )
        if r2.ok and r2.json():
            tag = r2.json()[0].get("name")
            out["latest_tag"] = tag
            out["published_at"] = None
        return out
    if r.ok:
        j = r.json()
        out["latest_tag"] = j.get("tag_name")
        out["published_at"] = j.get("published_at")
    return out


def days_since(iso_ts: str) -> int:
    if not iso_ts:
        return 10**6
    t = datetime.datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    return (datetime.datetime.now(datetime.timezone.utc) - t).days


def max_severity_from_scans() -> str:
    """
    Inspect artifacts/osv.json and artifacts/trivy.json (and others if present),
    return one of LOW/MEDIUM/HIGH/CRITICAL/NONE.
    """
    sev = "NONE"

    def bump(s):
        nonlocal sev
        if SEV_ORDER.get(s, 0) > SEV_ORDER.get(sev, 0):
            sev = s

    # OSV
    p = ART / "osv.json"
    if p.exists():
        try:
            j = json.load(open(p, encoding="utf-8"))
            # OSV schema varies; when scanning repo, results[].vulns[].database_specific.severity?
            for r in j.get("results", []):
                for pkg in r.get("packages", []):
                    for v in pkg.get("vulnerabilities", []):
                        s = (
                            v.get("severity")
                            or v.get("database_specific", {}).get("severity")
                            or ""
                        ).upper()
                        if not s and v.get("severity"):
                            if isinstance(v["severity"], list) and v["severity"]:
                                s = (
                                    v["severity"][0].get("type")
                                    or v["severity"][0].get("score")
                                    or ""
                                ).upper()
                        if "CRITICAL" in s:
                            bump("CRITICAL")
                        elif "HIGH" in s:
                            bump("HIGH")
                        elif "MEDIUM" in s:
                            bump("MEDIUM")
                        elif "LOW" in s:
                            bump("LOW")
        except Exception:
            pass

    # Trivy
    p = ART / "trivy.json"
    if p.exists():
        try:
            j = json.load(open(p, encoding="utf-8"))
            for res in j.get("Results", []):
                for v in res.get("Vulnerabilities", []) or []:
                    s = (v.get("Severity") or "").upper()
                    if s in SEV_ORDER:
                        bump(s)
        except Exception:
            pass

    # pip-audit / npm audit / cargo-audit can be added here similarly if desired
    return sev


def decide_status(
    tool: Dict[str, Any], latest: Dict[str, Any], sev: str
) -> Dict[str, Any]:
    status = "Adopted"
    status_on = now_iso()
    reason_code = ""
    reason = ""

    # archived -> quarantine
    if latest.get("archived"):
        return {
            "Status": "Quarantined",
            "StatusOn": status_on,
            "ReasonCode": "ARCHIVED",
            "Reason": "Upstream repo archived",
        }

    # staleness
    pub = latest.get("published_at")
    if pub and days_since(pub) > POLICY_MAX_DAYS:
        status = "Outdated"
        reason_code = "STALE"
        reason = f"Last release {days_since(pub)}d ago (> {POLICY_MAX_DAYS}d)"

    # CVE severity
    if sev != "NONE" and SEV_ORDER.get(sev, 0) >= SEV_ORDER.get(POLICY_MIN_SEV, 3):
        return {
            "Status": "Quarantined",
            "StatusOn": status_on,
            "ReasonCode": "VULN",
            "Reason": f"Max severity {sev} ≥ policy {POLICY_MIN_SEV}",
        }

    return {
        "Status": status,
        "StatusOn": status_on,
        "ReasonCode": reason_code,
        "Reason": reason,
    }


def main():
    inv = read_inventory()
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    sev = max_severity_from_scans()
    all_rows = []
    for t in inv:
        repo = t.get("RepoURL", "")
        meta = gh_latest_release(repo, token) if "github.com" in (repo or "") else {}
        latest = meta.get("latest_tag")
        published_at = meta.get("published_at")
        status = decide_status(t, meta, sev)

        row = {**t, "Version": latest or "", "LastUpdateCheck": now_iso(), **status}
        all_rows.append(row)

    # CSV header
    cols = [
        "Tool",
        "Category",
        "Chain",
        "Vendor",
        "License",
        "RepoURL",
        "MonitorMethod",
        "InstallMethod",
        "BinaryPath",
        "Version",
        "FirstSeen",
        "AdoptedOn",
        "LastUsed",
        "LastUpdateCheck",
        "Status",
        "StatusOn",
        "ReasonCode",
        "Reason",
        "ReplacedBy",
        "Owner",
        "Notes",
    ]
    csv_path = ART / "monitor_report.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in all_rows:
            w.writerow(r)

    with open(ART / "monitor_report.json", "w", encoding="utf-8") as f:
        json.dump(all_rows, f, indent=2)

    quarantined = [r for r in all_rows if r.get("Status") == "Quarantined"]
    with open(ART / "alerts.md", "w", encoding="utf-8") as f:
        f.write(f"# Tool Monitor Alerts — {now_iso()}\n\n")
        if quarantined:
            f.write("## Quarantined\n\n")
            for q in quarantined:
                f.write(f"- **{q['Tool']}** — {q.get('Reason','')}\n")
        else:
            f.write("No quarantined tools ✅\n")

    with open(ART / "quarantine.json", "w", encoding="utf-8") as f:
        json.dump(quarantined, f, indent=2)


if __name__ == "__main__":
    main()
