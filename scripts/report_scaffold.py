#!/usr/bin/env python3
import datetime
import pathlib
import subprocess

ART = pathlib.Path("artifacts")
ART.mkdir(exist_ok=True, parents=True)
T = pathlib.Path("audits/templates/report.md")
out = ART / "audit_report_draft.md"


def git(*args):
    try:
        return subprocess.check_output(["git", *args], text=True).strip()
    except Exception:
        return "N/A"


data = (
    T.read_text(encoding="utf-8")
    if T.exists()
    else """# Armor Audits — Security Review (Draft)

**Project:** {{PROJECT}}
**Commit:** {{COMMIT}}
**Date:** {{DATE}}

## Executive Summary
_TBD_

## Scope
- Repos / packages: _TBD_
- Commit: `{{COMMIT}}`

## Methodology (High-Level)
- Static: Slither, Mythril
- Fuzz: Foundry fuzz
- Invariants: Scribble + Foundry
- Supply-chain: SBOM + Grype

## Findings
_Use SWC mapping and include PoCs._

## Recommendations
_TBD_
"""
)
rep = data.replace(
    "{{DATE}}", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
)
rep = rep.replace("{{COMMIT}}", git("rev-parse", "--short", "HEAD"))
rep = rep.replace("{{PROJECT}}", pathlib.Path(".").resolve().name)
out.write_text(rep, encoding="utf-8")
print(f"Wrote {out}")
