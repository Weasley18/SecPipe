# SecPipe developer entry points. Every CI stage is a script in scripts/ci/, so
# `make scan` on a laptop runs exactly what the pipeline runs.
SHELL := /bin/bash
.DEFAULT_GOAL := help
PYTHON ?= python3.12
VENV   ?= .venv
BIN    := $(VENV)/bin
IMAGE  ?= secnotes:local
export PYTHON

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------- setup
.PHONY: setup
setup: $(VENV)/.installed ## Create the dev venv (hash-locked) and install pre-commit hooks
	$(BIN)/pre-commit install

$(VENV)/.installed: app/requirements.txt requirements/dev.txt requirements/secpipe.txt
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --quiet --require-hashes -r app/requirements.txt -r requirements/secpipe.txt -r requirements/dev.txt
	$(BIN)/pip install --quiet --no-deps --no-build-isolation -e .
	touch $@

.PHONY: lock
lock: ## Re-compile every hash-locked requirements file
	cd app && $(abspath $(BIN))/pip-compile -q --strip-extras --generate-hashes -o requirements.txt requirements.in
	cd requirements && $(abspath $(BIN))/pip-compile -q --strip-extras --generate-hashes --allow-unsafe -o secpipe.txt secpipe.in
	cd requirements && $(abspath $(BIN))/pip-compile -q --strip-extras --generate-hashes --allow-unsafe -o dev.txt dev.in
	for f in sast iac sca; do $(BIN)/pip-compile -q --strip-extras --generate-hashes --allow-unsafe -o scripts/ci/requirements/$$f.txt scripts/ci/requirements/$$f.in; done

.PHONY: secrets
secrets: ## Generate random local secrets for docker compose (.secrets/, git-ignored)
	./scripts/gen-local-secrets.sh

# -------------------------------------------------------------- quality
.PHONY: test test-app test-secpipe lint typecheck rules-test policy-validate kyverno-test tf-lint check
test: test-app test-secpipe ## Run all unit tests

test-app: $(VENV)/.installed ## SecNotes tests (security regression tests for every fix)
	$(BIN)/pytest app/tests --cov=secnotes --cov-report=term-missing:skip-covered --cov-report=xml:coverage-app.xml

test-secpipe: $(VENV)/.installed ## Aggregator/policy/correlator tests (>= 85% coverage enforced)
	$(BIN)/pytest secpipe/tests --cov=secpipe --cov-report=term-missing:skip-covered --cov-report=xml:coverage-secpipe.xml --cov-fail-under=85

lint: $(VENV)/.installed ## ruff lint + format check
	$(BIN)/ruff check app secpipe
	$(BIN)/ruff format --check app secpipe

typecheck: $(VENV)/.installed ## mypy --strict
	$(BIN)/mypy

rules-test: ## Custom Semgrep rule tests and custom Checkov policy tests
	source scripts/ci/lib.sh && "$$(python_tools sast)/semgrep" --test --metrics off policy/semgrep/
	./scripts/ci/checkov-policy-test.sh

policy-validate: $(VENV)/.installed ## Validate policy.yaml against its JSON Schema
	$(BIN)/secpipe policy validate policy/policy.yaml

kyverno-test: ## Kyverno policy unit tests
	./scripts/ci/kyverno-test.sh

TF_ROOTS := infra/envs/local infra/envs/aws infra/bootstrap
tf-lint: ## terraform fmt/validate + tflint on every root module
	terraform fmt -check -recursive infra
	for d in $(TF_ROOTS); do terraform -chdir=$$d init -backend=false -input=false >/dev/null && terraform -chdir=$$d validate || exit 1; done
	cd infra && tflint --config "$$PWD/.tflint.hcl" --init && tflint --config "$$PWD/.tflint.hcl" --recursive

check: lint typecheck test rules-test policy-validate kyverno-test tf-lint ## Everything CI's quality workflow runs

# ------------------------------------------------------------------ scans
.PHONY: scan scan-secrets scan-sast scan-sca scan-iac scan-dockerfile scan-image build gate
scan: ## Run every static scanner exactly as CI does (reports/)
	IMAGE=$(IMAGE) ./scripts/ci/scan-all.sh

scan-secrets: ## Gitleaks over full history
	./scripts/ci/gitleaks.sh
scan-sast: ## Semgrep + Bandit
	./scripts/ci/sast.sh
scan-sca: ## OSV-Scanner, pip-audit, licences (+ Snyk with SNYK_TOKEN)
	./scripts/ci/sca.sh
scan-iac: ## Checkov, Trivy config, Kubescape, zizmor
	./scripts/ci/iac.sh
scan-dockerfile: ## Hadolint
	./scripts/ci/hadolint.sh
build: ## Build the hardened image
	docker build -f app/Dockerfile -t $(IMAGE) .
scan-image: build ## Trivy image scan + Syft SBOM
	./scripts/ci/scan-image.sh $(IMAGE)

gate: $(VENV)/.installed ## Run the gate over reports/ like Gate 1 (EXPECT to override)
	$(BIN)/secpipe gate --reports reports --expect "$${EXPECT:-gitleaks,semgrep,bandit,osv,pip-audit,hadolint,trivy,checkov}" \
	  --policy policy/policy.yaml --branch "$${BRANCH:-main}" --stage gate-1 --out out --source-root .

# --------------------------------------------------------- local cluster
.PHONY: up down cluster platform deploy monitoring demo drill dast teardown
up: secrets ## docker compose: hardened app + Postgres on http://127.0.0.1:8000
	docker compose up -d --build

down: ## Stop docker compose
	docker compose down -v

cluster: ## kind cluster (Terraform, Calico, audit logging) + platform (Kyverno, ingress, cert-manager)
	./scripts/cluster-up.sh

deploy: ## Build, kind-load and deploy the hardened image (local overlay, Ingress + TLS)
	./scripts/deploy.sh

monitoring: ## Prometheus, Grafana, Loki, Alloy, Alertmanager, Falco, SecPipe exporter + correlator
	./scripts/install-monitoring.sh

dast: ## ZAP baseline + authenticated API scan against the local deployment
	kubectl -n secnotes port-forward --address 127.0.0.1 svc/secnotes-api 18080:80 >/dev/null 2>&1 & pf=$$!; \
	trap "kill $$pf" EXIT; sleep 3; ./scripts/ci/zap.sh http://127.0.0.1:18080 $(ZAP_TIERS)

demo: ## The 5-minute demo: admission rejections, attack drill, quarantine
	./scripts/demo.sh

drill: ## Simulated attack chain; measures time to detect for each step
	./scripts/drill.sh

teardown: ## Destroy the kind cluster
	./scripts/teardown.sh

.PHONY: clean
clean: ## Remove local scan output and caches
	rm -rf reports out baseline build .pytest_cache .mypy_cache .ruff_cache coverage*.xml .coverage
