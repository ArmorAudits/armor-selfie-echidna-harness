#!/usr/bin/env bash
set -euo pipefail
OUT="artifacts/evidence-$(date -u +%Y%m%dT%H%M%SZ).zip"
mkdir -p artifacts
zip -r "$OUT" artifacts -x "*.zip" || true
echo "Bundle: $OUT"
if command -v cosign >/dev/null 2>&1; then
  COSIGN_EXPERIMENTAL=1 cosign attest --predicate artifacts/sbom.spdx.json --type spdx "$OUT" || true
fi
