#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -lt 3 ]; then
  echo "Usage: $0 OWNER/REPO WORKFLOW_PATH REF [key=value ...]" >&2; exit 2
fi
REPO="$1"; WFPATH="$2"; WFNAME="$(basename "$WFPATH")"; REF="$3"; shift 3 || true
inputs=(); for kv in "$@"; do inputs+=( -f "$kv" ); done
gh workflow run "$WFPATH" -R "$REPO" --ref "$REF" "${inputs[@]}"
RID=""
for _ in {1..30}; do
  RID="$(gh run list -R "$REPO" --workflow "$WFNAME" --branch "$REF" \
       --limit 1 --json databaseId -q '.[0].databaseId // ""' || true)"
  [ -n "${RID:-}" ] && break; sleep 2
done
[ -z "${RID:-}" ] && { echo "No run found for $WFNAME on $REF"; exit 1; }
gh run watch "$RID" -R "$REPO" --exit-status
gh run view  "$RID" -R "$REPO" --log
