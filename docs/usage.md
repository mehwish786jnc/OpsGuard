# Usage

## Scan Kubernetes manifests

```bash
opsguard scan ./k8s
```

## Scan Helm charts & Kustomize overlays

OpsGuard auto-detects templated sources and renders them to plain manifests
before scanning — no need to render by hand:

- A directory containing `Chart.yaml` is rendered with `helm template`.
- A directory containing `kustomization.yaml` is rendered with
  `kustomize build` (falling back to `kubectl kustomize`).

```bash
# Render a chart with its default values and scan the result
opsguard scan ./charts/payments

# Pass one or more Helm values files (repeatable)
opsguard scan ./charts/payments --values prod.yaml --values region-eu.yaml

# Render a Kustomize overlay
opsguard scan ./overlays/production

# Try the bundled examples
opsguard scan examples/helm-chart --fail-on never
opsguard scan examples/kustomize --fail-on never
```

Rendering requires the matching tool on your `PATH` (`helm`, and `kustomize`
or `kubectl`). If a tool is missing or a render fails, OpsGuard prints a
`warning:` and skips that source — raw YAML elsewhere in the scan is unaffected.
Charts and overlays nested inside a scanned directory are rendered as a unit,
so their raw template files are never mis-parsed as manifests.

Use `--no-render` to disable this and scan only raw YAML (templated sources are
then skipped, not parsed):

```bash
opsguard scan ./k8s --no-render
```

## Scan a Terraform plan

OpsGuard reads the JSON form of a plan (`terraform show -json`):

```bash
terraform plan -out tfplan.binary
terraform show -json tfplan.binary > tfplan.json
opsguard scan --tf-plan tfplan.json
```

## Scan both and gate the build

```bash
opsguard scan ./k8s --tf-plan tfplan.json --fail-on high --format sarif -o opsguard.sarif
```

Try it on the bundled examples:

```bash
opsguard scan examples/risky-k8s --tf-plan examples/terraform/tfplan.json --fail-on never
```

## Output formats

| Format | Flag | Use for |
|---|---|---|
| Terminal | `-f terminal` (default) | Local development |
| Markdown | `-f markdown` | PR comments |
| JSON | `-f json` | Pipelines / custom tooling |
| SARIF | `-f sarif` | GitHub code scanning / Security tab |

## Common options

| Option | Default | Description |
|---|---|---|
| `--fail-on` | `high` | Exit non-zero at/above this severity (`info`…`critical`, or `never`). |
| `--min-severity` | `info` | Hide findings below this severity. |
| `--disable` | — | Suppress one or more rules by id, e.g. `--disable K8S-IMG-001`. |
| `--values` | — | Helm values file(s) for `helm template` (repeatable). |
| `--no-render` | off | Scan raw YAML only; skip Helm/Kustomize rendering. |
| `--format`, `-f` | `terminal` | Output format (see above). |
| `--output`, `-o` | stdout | Write the report to a file. |
| `--ai` / `--no-ai` | off | Attach AI explanations (see [AI explanations](ai.md)). |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding reached the `--fail-on` gate. |
| `1` | A finding at or above the gate was found. |
| `2` | Usage error (bad arguments, unknown format/severity). |
