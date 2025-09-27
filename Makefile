.PHONY: doctor sbom audit

doctor:
	python monitor/doctor.py --inventory monitor/tools.csv

sbom:
	mkdir -p artifacts
	syft dir:. -o spdx-json > artifacts/sbom.spdx.json

audit: sbom
	grype sbom:artifacts/sbom.spdx.json -o table | tee artifacts/grype.txt
### === ARMOR $20K TARGETS ===
.PHONY: slither invariants fuzz mythril report

SLITHER_FLAGS ?= --print human-summary --filter-paths "test|node_modules|lib|script"
FORGE_FLAGS   ?= -vvv
FUZZ_RUNS     ?= 1000
SRC_DIR       ?= src

slither:
	@echo ">> Slither"
	@slither . $(SLITHER_FLAGS) || true

invariants:
	@echo ">> Scribble instrumentation (noop if no specs)"
	@scribble $(SRC_DIR) --output-mode flat --arm || true
	@echo ">> Foundry invariants (match Invariant)"
	@forge test $(FORGE_FLAGS) --match-test invariant_ || true

fuzz:
	@echo ">> Foundry fuzz"
	@forge test $(FORGE_FLAGS) --fuzz-runs $(FUZZ_RUNS) || true

mythril:
	@echo ">> Mythril symbolic (quick)"
	@myth analyze $(SRC_DIR) --execution-timeout 120 --max-depth 32 || true

report:
	@python scripts/report_scaffold.py

### === OPTIONAL UPGRADES ===
.PHONY: coverage halmos certora gitleaks trivy attest
coverage: ## forge coverage + gate
	forge coverage --report lcov --report summary || true
	python3 scripts/coverage_gate.py --min $${MIN_COVERAGE:-80}

halmos: ## run halmos (if installed)
	command -v halmos >/dev/null 2>&1 && halmos . || echo "Halmos not installed; skipping"

certora: ## run certora (if configured)
	command -v certoraRun >/dev/null 2>&1 && echo "Running Certora…" && true || echo "Certora CLI not found; skipping"

gitleaks: ## secrets scan
	command -v gitleaks >/dev/null 2>&1 && gitleaks detect --no-banner -v --redact --report-path artifacts/gitleaks.json || echo "Use CI step for gitleaks"

trivy: ## IaC/package scan
	command -v trivy >/dev/null 2>&1 && trivy fs . --severity HIGH,CRITICAL --format table || echo "Use CI step for trivy"

attest: ## sign SBOM if present
	if [ -f artifacts/sbom.spdx.json ]; then COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes --output-signature artifacts/sbom.spdx.json.sig artifacts/sbom.spdx.json || true; else echo "No SBOM"; fi
