.PHONY: doctor sbom audit

doctor:
	python monitor/doctor.py --inventory monitor/tools.csv

sbom:
	mkdir -p artifacts
	syft dir:. -o spdx-json > artifacts/sbom.spdx.json

audit: sbom
	grype sbom:artifacts/sbom.spdx.json -o table | tee artifacts/grype.txt
