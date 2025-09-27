# DVT Selfie — Echidna Harness
...content...
## Security
- Make targets: `make doctor`, `make sbom`, `make audit` (SBOM + grype)
- CI: see `.github/workflows/security-monitor.yml`


[![Security Monitor](https://github.com/ArmorAudits/armor-selfie-echidna-harness/actions/workflows/security-monitor.yml/badge.svg)](https://github.com/ArmorAudits/armor-selfie-echidna-harness/actions/workflows/security-monitor.yml)


## Armor Audit CI
[![Armor Audit](https://github.com/${GITHUB_REPOSITORY:-ArmorAudits/armor-selfie-echidna-harness}/actions/workflows/armor-audit.yml/badge.svg)](./.github/workflows/armor-audit.yml)

- Kick it off with **Actions → Armor Audit → Run workflow**
- Artifacts: `artifacts/` (report draft, SBOM, logs)
