# Changelog

All notable changes to OpsGuard are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
