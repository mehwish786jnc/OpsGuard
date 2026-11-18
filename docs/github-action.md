# GitHub Action

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

See
[`.github/workflows/opsguard-example.yml`](https://github.com/mehwish786jnc/OpsGuard/blob/main/.github/workflows/opsguard-example.yml)
for a complete, working example.

## Inputs

| Input | Default | Description |
|---|---|---|
| `paths` | — | Space/newline-separated paths of Kubernetes manifests to scan. |
| `tf-plan` | — | Path to a Terraform plan JSON file (`terraform show -json`). |
| `fail-on` | `high` | Fail the job at/above this severity, or `never`. |
| `sarif-file` | — | Write SARIF to this path for the Security tab. |

## What the PR comment looks like

OpsGuard posts a single, updated-in-place comment that summarizes findings by
severity, recommends whether to block the merge, and expands each finding with
its impact, remediation and blast radius.
