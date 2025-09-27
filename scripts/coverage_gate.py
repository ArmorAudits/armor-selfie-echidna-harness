#!/usr/bin/env python3
import sys, re, pathlib, argparse
p = pathlib.Path("lcov.info")
ap = argparse.ArgumentParser()
ap.add_argument("--min", type=float, default=float((pathlib.os.getenv("MIN_COVERAGE") or 80)))
a = ap.parse_args()
if not p.exists():
    print("coverage_gate: lcov.info not found (skipping, exit 0)")
    sys.exit(0)
LF = LH = 0
for line in p.read_text().splitlines():
    if line.startswith("LF:"):
        LF += int(line.split(":",1)[1])
    elif line.startswith("LH:"):
        LH += int(line.split(":",1)[1])
pct = (100.0*LH/LF) if LF else 0.0
print(f"coverage_gate: {LH}/{LF} lines -> {pct:.2f}% (min {a.min:.2f}%)")
if pct + 1e-9 < a.min:
    print("coverage_gate: FAIL (below threshold)"); sys.exit(2)
print("coverage_gate: OK"); sys.exit(0)
