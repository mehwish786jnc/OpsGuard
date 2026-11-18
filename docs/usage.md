# Usage

## Scan Kubernetes manifests

```bash
opsguard scan ./k8s
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
| `--format`, `-f` | `terminal` | Output format (see above). |
| `--output`, `-o` | stdout | Write the report to a file. |
| `--ai` / `--no-ai` | off | Attach AI explanations (see [AI explanations](ai.md)). |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding reached the `--fail-on` gate. |
| `1` | A finding at or above the gate was found. |
| `2` | Usage error (bad arguments, unknown format/severity). |
