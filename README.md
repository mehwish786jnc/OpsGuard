<div align="center">

# 🛡️ OpsGuard

### Catch the change before it breaks production.

**Open-source production change intelligence for Kubernetes & Terraform.**

OpsGuard reviews infrastructure changes in a pull request, finds the ones that
could take down production — public exposure, destructive changes, insecure
config, missing reliability guardrails — explains the blast radius, and reports
back in the PR *before* anything is merged.

[![CI](https://github.com/mehwish786jnc/OpsGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/mehwish786jnc/OpsGuard/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

</div>

---

## Why OpsGuard?

Passing CI does **not** mean a change is safe for production. A perfectly
"green" pull request can still:

- 🌐 Expose an internal service to the internet
- 💥 Delete or replace a production database
- 🔓 Open a security group to `0.0.0.0/0`
- ⚙️ Ship a workload with no probes or resource limits
- 🔑 Grant `*:*` IAM permissions
- 🧩 Remove a secret another service depends on

Generic AI reviewers look at code. **OpsGuard understands what an infrastructure
change can break across your whole environment** — and it does so with
*deterministic rules*, not a coin-flipping LLM.

> **Design principle:** Security decisions are made by deterministic rules. AI is
> used only to *explain* findings and suggest fixes — never to decide whether a
> deployment is safe.

---

## How it works

```mermaid
flowchart LR
    A[Pull Request] --> B[OpsGuard Engine]
    B --> C[Parse K8s YAML + Terraform plan]
    C --> D[Dependency graph<br/>NetworkX]
    D --> E[Deterministic rules]
    E --> F[Blast-radius analysis]
    F --> G[Risk scoring]
    G --> H[AI explanations<br/>optional]
    H --> I[PR comment · SARIF · JSON]
```

1. **Parse** Kubernetes manifests and Terraform plan JSON.
2. **Graph** the relationships between Deployments, Services, Ingress, Secrets,
   ConfigMaps and cloud resources.
3. **Evaluate** deterministic security & reliability rules.
4. **Propagate** blast radius: a risky Secret change is reported *with* every
   service that depends on it.
5. **Score & explain**, then report in the format your pipeline needs.

---

## Quick start

### Install

```bash
pip install opsguard        # from PyPI (once published)
# or, from source:
git clone https://github.com/mehwish786jnc/OpsGuard && cd OpsGuard
pip install -e ".[dev]"
```

### Scan

```bash
# Scan Kubernetes manifests
opsguard scan ./k8s

# Scan a Terraform plan
terraform plan -out tfplan.binary
terraform show -json tfplan.binary > tfplan.json
opsguard scan --tf-plan tfplan.json

# Scan both, fail the build on HIGH+, emit SARIF for the GitHub Security tab
opsguard scan ./k8s --tf-plan tfplan.json --fail-on high --format sarif -o opsguard.sarif
```

Try it on the bundled examples:

```bash
opsguard scan examples/risky-k8s --tf-plan examples/terraform/tfplan.json --fail-on never
```

### Output formats

| Format | Flag | Use for |
|---|---|---|
| Terminal | `-f terminal` (default) | Local development |
| Markdown | `-f markdown` | PR comments |
| JSON | `-f json` | Pipelines / custom tooling |
| SARIF | `-f sarif` | GitHub code scanning / Security tab |

---

## GitHub Action

Add OpsGuard to any repo in minutes. It posts a sticky report comment on every
PR and can upload SARIF to the Security tab.

```yaml
# .github/workflows/opsguard.yml
name: OpsGuard
on: pull_request
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  opsguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mehwish786jnc/OpsGuard@v1
        with:
          paths: "k8s"
          tf-plan: "tfplan.json"   # optional
          fail-on: "high"
          sarif-file: "opsguard.sarif"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: opsguard.sarif
```

See [`.github/workflows/opsguard-example.yml`](.github/workflows/opsguard-example.yml)
for a complete, working example.

---

## Rules

Run `opsguard rules` to list everything. Current coverage:

### Kubernetes

| ID | Severity | Detects |
|---|---|---|
| `K8S-SEC-001` | Critical | Privileged container |
| `K8S-SEC-002` | High | Host network namespace |
| `K8S-SEC-003` | High | Host PID/IPC namespace |
| `K8S-SEC-004` | High | Container may run as root |
| `K8S-SEC-005` | Medium | Privilege escalation not disabled |
| `K8S-SEC-006` | High | Dangerous Linux capability added |
| `K8S-SEC-007` | Low | Service account token auto-mounted |
| `K8S-EXPOSURE-001` | High | Public LoadBalancer exposure |
| `K8S-EXPOSURE-002` | Medium | NodePort exposure |
| `K8S-EXPOSURE-003` | Medium | Ingress without TLS |
| `K8S-REL-001` | Medium | Missing liveness/readiness probe |
| `K8S-REL-002` | Medium | Missing resource requests/limits |
| `K8S-REL-003` | Medium | Single replica (no redundancy) |
| `K8S-IMG-001` | Medium | Unpinned / `latest` image tag |

### Terraform

| ID | Severity | Detects |
|---|---|---|
| `TF-DESTROY-001` | Critical | Destroy/replace of a stateful resource |
| `TF-NET-001` | High | Security group open to the internet |
| `TF-S3-001` | High/Critical | Public S3 bucket |
| `TF-RDS-001` | High | Publicly accessible database |
| `TF-RDS-002` | Medium | Unencrypted database storage |
| `TF-IAM-001` | High/Critical | Wildcard IAM permissions |

Writing a new rule is a few lines of Python — see
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## AI explanations (optional)

AI is strictly an *explainer*. Findings exist with or without it.

```bash
opsguard scan ./k8s --ai --ai-provider ollama --ai-model llama3
opsguard scan ./k8s --ai --ai-provider gemini   # needs GEMINI_API_KEY
```

The default `offline` provider needs no network and composes a clear
explanation from the finding itself — ideal for air-gapped CI.

---

## Architecture

```
src/opsguard/
├── scanner/      # Parse K8s YAML and Terraform plan JSON
├── rules/        # Deterministic security & reliability rules
├── graph/        # NetworkX dependency graph + blast radius
├── risk/         # Composite risk scoring
├── ai/           # Explanations (offline / Ollama / Gemini)
├── report/       # terminal · markdown · json · sarif
├── engine.py     # Orchestration pipeline
└── cli.py        # Typer CLI
```

---

## Roadmap

- [x] **M1 — Infrastructure scanner:** K8s YAML + Terraform plan parsing & rules
- [x] **M2 — Dependency graph:** blast-radius across deployments/services/secrets
- [x] **M3 — Risk intelligence:** severity, scoring, AI explanations
- [x] **M4 — Open-source release:** GitHub Action, PR reports, SARIF, docs
- [ ] Helm chart & Kustomize rendering
- [ ] OPA/Rego custom policy support
- [ ] Trivy / Checkov / KubeLinter enrichment
- [ ] Baseline diffing for Kubernetes (detect removed env vars/secrets)
- [ ] GitLab & Bitbucket integrations

---

## Contributing

OpsGuard is built to be easy to contribute to — most value lands as new rules.
Read [CONTRIBUTING.md](CONTRIBUTING.md), pick a rule idea, and open a PR.

## License

[Apache-2.0](LICENSE). Business-friendly and safe for enterprise adoption.
