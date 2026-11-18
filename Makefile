# OpsGuard developer tasks. Run `make help` for the list.
.DEFAULT_GOAL := help
.PHONY: help install test cov lint fmt fmt-check typecheck check docs docs-serve site web demo build clean

PYTHON ?= python

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with dev extras + pre-commit hooks
	$(PYTHON) -m pip install -e ".[dev,ai]"
	pre-commit install || true

test: ## Run the test suite
	pytest

cov: ## Run tests with a coverage report
	pytest --cov=opsguard --cov-report=term-missing --cov-report=xml

lint: ## Lint with ruff
	ruff check src tests

fmt: ## Auto-format with ruff
	ruff format src tests
	ruff check --fix src tests

fmt-check: ## Check formatting without writing
	ruff format --check src tests

typecheck: ## Static type-check with mypy
	mypy src

check: lint fmt-check typecheck test ## Run every quality gate

docs: ## Build the documentation site
	mkdocs build --strict

docs-serve: ## Serve the docs locally with live reload
	mkdocs serve

web: ## Preview the landing page locally at http://localhost:8080
	$(PYTHON) -m http.server 8080 --directory web

site: ## Assemble the full Pages site (landing at /, docs at /docs) into public/
	rm -rf public && mkdir -p public
	cp -R web/. public/
	mkdocs build --strict -d public/docs
	@echo "Built public/ — open public/index.html"

demo: ## Regenerate the terminal demo asset (assets/demo.svg)
	$(PYTHON) scripts/gen_demo.py

build: ## Build sdist and wheel
	$(PYTHON) -m pip install --upgrade build
	$(PYTHON) -m build

clean: ## Remove build/test artifacts
	rm -rf dist build *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov coverage.xml site public
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
