.PHONY: help install dev test test-slow test-golden test-all lint format clean db-init smoke summary doctor setup-hooks submodules resync-main audit audit-bundle runbook-local

VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

help:
	@echo "exploitbench targets:"
	@echo "  install       create venv + install package + dev deps"
	@echo "  test          unit + golden tests (no Docker, no API)"
	@echo "  test-slow     slow tests (Docker required, no API)"
	@echo "  test-golden   tier-2 parity tests vs imported-opus eval data"
	@echo "  test-all      run everything"
	@echo "  smoke         build sample env + run --mock-llm"
	@echo "  doctor        print env / docker / deps health check"
	@echo "  summary       per-benchmark spend / status table"
	@echo "  lint / format ruff check / format"
	@echo "  setup-hooks   point git at .githooks/ (refuses commits on main)"
	@echo "  resync-main   hard-align local main with origin/main"
	@echo "  audit-bundle  pack one benchmark's run-dirs + sha256 manifest"
	@echo "                into audit-bundles/<id>-<ts>.tar.gz."
	@echo "                usage: make audit-bundle BENCHMARK_ID=<id>"
	@echo "  runbook-local cp docs/RUNBOOK.md → RUNBOOK.local.md (gitignored)"
	@echo "  clean         delete venv + caches"

install: $(VENV)
	$(PIP) install -e .[dev]
	@# Tighten .env permissions if it exists and is too-permissive (default
	@# umask creates 644 = world-readable, which leaks API keys to any
	@# local user). Idempotent: chmod 600 is a no-op when already 600.
	@if [ -f .env ]; then \
	    chmod 600 .env && echo "tightened .env permissions to 600"; \
	fi

# Pull bench-v8 (and any future submodules). Idempotent — safe to re-run.
$(VENV):
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

dev: install

db-init:
	$(PY) -c "from exploitbench.db.schema import init_db; init_db()"

test:
	$(VENV)/bin/pytest -q -m "not slow"

test-slow:
	$(VENV)/bin/pytest -q -m "slow"

test-golden:
	$(VENV)/bin/pytest -q -m "golden"

test-all:
	$(VENV)/bin/pytest -q

lint:
	$(VENV)/bin/ruff check exploitbench

format:
	$(VENV)/bin/ruff format exploitbench

smoke: $(VENV)
	bash scripts/build_sample_env.sh
	$(VENV)/bin/exploitbench benchmark --mock-llm

summary:
	$(VENV)/bin/exploitbench summary

doctor:
	$(VENV)/bin/exploitbench doctor

# Bootstrap a personal RUNBOOK.local.md from the canonical methodology doc.
# RUNBOOK.local.md is gitignored (*.local.md) — your checkboxes, in-flight
# notes, and operator state stay out of commits. Refresh as needed when
# docs/RUNBOOK.md is updated.
runbook-local:
	@if [ -f RUNBOOK.local.md ]; then \
		echo "RUNBOOK.local.md already exists — refusing to overwrite."; \
		echo "Delete it first if you want to refresh from docs/RUNBOOK.md."; \
		exit 1; \
	fi
	@cp docs/RUNBOOK.md RUNBOOK.local.md
	@echo "Created RUNBOOK.local.md (gitignored). Check items off as you go."

clean:
	rm -rf $(VENV) build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +

# Hard-align local main with origin/main. Safe because per CLAUDE.md we
# never commit to main directly; any divergent commits are obsolete
# pre-rebase predecessors of work that landed on origin/main with new SHAs.
