# Contributing to OpsGuard

Thanks for helping make production safer! OpsGuard is designed so that the most
valuable contribution — **a new rule** — is also the easiest to add.

## Development setup

```bash
git clone https://github.com/mehwish786jnc/OpsGuard && cd OpsGuard
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest          # run the test suite
ruff check src tests
```

## Project layout

| Path | Responsibility |
|---|---|
| `src/opsguard/scanner/` | Turn raw files into normalized resource objects |
| `src/opsguard/rules/` | Deterministic rules (the core value) |
| `src/opsguard/graph/` | Dependency graph & blast radius |
| `src/opsguard/risk/` | Risk scoring |
| `src/opsguard/ai/` | Explanations (never decisions) |
| `src/opsguard/report/` | Output formatters |
| `examples/` | Realistic fixtures used by docs and tests |
| `tests/` | pytest suite |

## Writing a new rule

Rules self-register via a decorator. A Kubernetes rule only needs to implement
`evaluate`:

```python
from opsguard.models import Finding, Severity
from opsguard.rules.base import KubernetesRule, register
from opsguard.scanner.kubernetes import K8sResource


@register
class DisallowDefaultNamespace(KubernetesRule):
    id = "K8S-NS-001"                 # stable, unique, never changes once merged
    title = "Workload deployed to the default namespace"
    severity = Severity.LOW
    applies_to = ("Deployment", "StatefulSet")

    def evaluate(self, resource: K8sResource):
        if (resource.namespace or "default") != "default":
            return []
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                resource=resource.ref,
                message=f"{resource.name} is deployed to the 'default' namespace.",
                impact="The default namespace lacks isolation and is easy to misconfigure.",
                remediation="Deploy into a dedicated, labelled namespace.",
            )
        ]
```

A Terraform rule is the same, but subclasses `TerraformRule` and evaluates a
`TfResourceChange` (which exposes `change_action`, `is_destroy`, `config()`).

### Rule guidelines

1. **Deterministic only.** No network calls, no LLM, no randomness. Same input →
   same output.
2. **One risk per rule.** Keep rules focused and easy to reason about.
3. **Actionable remediation.** Tell the engineer exactly what to change.
4. **Stable IDs.** Once a rule id is released, never change it (people suppress
   by id). Follow the `AREA-TOPIC-NNN` convention.
5. **Right severity.** Critical = data loss / full compromise. High = likely
   exploitable or internet-facing. Medium/Low = hardening & reliability.
6. **Add tests and a fixture.** Prove it fires on a bad input and is silent on a
   good one.

## Tests

- Unit-test each rule with a minimal manifest/plan (see `tests/`).
- Add realistic examples under `examples/` when they help users understand a
  risk.
- All PRs must pass `pytest` and `ruff check`.

## Commit & PR conventions

- Keep PRs focused. One rule or one feature per PR is ideal.
- Describe the risk a rule catches and link a reference (docs/CVE) where useful.
- By contributing, you agree your work is licensed under Apache-2.0.

## Code of conduct

Be respectful and constructive. We want OpsGuard to be a welcoming project for
first-time open-source contributors.
