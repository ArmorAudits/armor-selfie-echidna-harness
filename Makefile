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
