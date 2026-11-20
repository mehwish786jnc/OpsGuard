# Changelog

All notable changes to OpsGuard are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Helm & Kustomize rendering** — `opsguard scan` now auto-detects Helm charts
  (`Chart.yaml`) and Kustomize overlays (`kustomization.yaml`) and renders them
  to plain manifests (via `helm template` / `kustomize build`, falling back to
  `kubectl kustomize`) before applying the existing rule set. New `--values`
  (repeatable Helm values files) and `--no-render` flags; bundled
  `examples/helm-chart` and `examples/kustomize`. Missing tools or failed
  renders are reported as warnings and skipped, never aborting the scan.
- **Marketing landing page** (`web/`) — a bespoke, responsive, dark/light
  product site (hero, feature grid, pipeline, quick-start tabs, rules coverage)
  deployed to GitHub Pages at the site root, with the docs served under `/docs/`.
- **Documentation site** (MkDocs Material) with installation, usage, GitHub
  Action, rules, AI and architecture pages, auto-deployed to GitHub Pages.
- **Code of Conduct** (Contributor Covenant 2.1), **Dependabot** config,
  **pre-commit** hooks, a **`CITATION.cff`**, a **`Makefile`** of developer
  tasks, and a standalone **`ROADMAP.md`**.
- **Terminal demo asset** (`assets/demo.svg`), regenerated via
  `scripts/gen_demo.py` / `make demo`, embedded in the README.

### Changed

- CI now runs a dedicated quality gate (ruff lint, `ruff format --check`,
  `mypy`) and uploads coverage to Codecov. Test coverage raised from 86% to 92%.
- Adopted `ruff format` across the codebase and added a strict `mypy` config.

## [0.1.0] - 2026-11-05

### Added

- **Infrastructure scanners** for Kubernetes manifests (multi-document YAML) and
  Terraform plan JSON (`terraform show -json`).
- **19 deterministic rules** across security, public exposure, reliability and
  image hygiene (Kubernetes) and destructive/replace changes, open security
  groups, public S3/RDS and wildcard IAM (Terraform).
- **Dependency graph** (NetworkX) linking Deployments, Services, Ingress,
  Secrets and ConfigMaps, with **blast-radius** analysis attached to findings.
- **Risk scoring** combining severity, blast radius and change type.
- **AI explanations** with a deterministic offline provider plus optional Ollama
  and Gemini backends (explanations only — never risk decisions).
- **Reports** in terminal, Markdown (PR comments), JSON and SARIF 2.1.0.
- **Typer CLI**: `opsguard scan` and `opsguard rules`, with severity gating.
- **GitHub Action** (composite) that posts a sticky PR comment, writes SARIF and
  gates merges.
- Realistic example fixtures (safe vs. risky) and a 52-case test suite.

[Unreleased]: https://github.com/mehwish786jnc/OpsGuard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mehwish786jnc/OpsGuard/releases/tag/v0.1.0
