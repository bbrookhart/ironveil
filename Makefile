UV ?= uv
UV_CACHE_DIR ?= .uv-cache
UV_LINK_MODE ?= copy
export UV_CACHE_DIR UV_LINK_MODE
RUN := $(UV) run

.PHONY: bootstrap lint typecheck test test-properties test-scenarios mutation security sbom provenance build sign verify release lab-up health experiment evaluate evidence docs lab-down clean

bootstrap:
	$(UV) sync --all-extras
	$(RUN) ironveil lab init

lint:
	$(RUN) ruff check .
	$(RUN) ruff format --check .

typecheck:
	$(RUN) mypy

test:
	$(RUN) pytest tests/unit tests/integration tests/policy tests/architecture

test-properties:
	$(RUN) pytest tests/property

test-scenarios:
	$(RUN) pytest tests/scenarios

mutation:
	$(RUN) python scripts/mutation_check.py

security:
	$(RUN) python scripts/security_check.py

sbom:
	$(RUN) ironveil sbom verify golden

provenance:
	$(RUN) ironveil provenance verify golden

build:
	$(RUN) ironveil lab init
	$(RUN) ironveil build inspect .ironveil/artifacts/veilnode-1.0.0.json

sign:
	$(RUN) ironveil signature verify golden

verify:
	$(RUN) ironveil release verify RELEASE-00001

release: build sbom provenance sign verify evidence

lab-up:
	$(RUN) ironveil lab up

health:
	$(RUN) ironveil lab health

experiment:
	$(RUN) ironveil experiment run BROKEN-SEAL

evaluate: experiment

evidence:
	$(RUN) ironveil evidence verify RELEASE-00001

docs:
	$(RUN) python scripts/docs_check.py

lab-down:
	$(RUN) ironveil lab down

clean:
	$(RUN) python scripts/clean.py
