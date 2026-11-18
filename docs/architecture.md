# Architecture

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

## The pipeline

```
parse  ─▶  build dependency graph  ─▶  run deterministic rules
       ─▶  annotate blast radius   ─▶  score risk
       ─▶  (optional) AI explanations
```

Security decisions come entirely from the deterministic rules. The graph, score
and AI layers only *enrich* findings — they never create or suppress a risk.

## Key modules

| Module | Responsibility |
|---|---|
| `scanner.kubernetes` / `scanner.terraform` | Normalize raw files into `K8sResource` / `TfResourceChange`. |
| `rules.base` | The `Rule` framework and self-registering `@register` decorator. |
| `graph.dependency` | Builds a `DiGraph` where ancestors of a node are its blast radius. |
| `risk` | Combines severity, blast radius and change type into a 0–100 score. |
| `ai` | Explanation-only layer with offline/Ollama/Gemini providers. |
| `report.formatters` | Renders a `ScanResult` to terminal, Markdown, JSON or SARIF. |

## Data model

Everything flows through dependency-free dataclasses in `opsguard.models`:

- `Severity` — ordered `IntEnum` (`INFO` < `LOW` < … < `CRITICAL`).
- `ResourceRef` — stable reference with a `node_id` used as the graph key.
- `Finding` — one risk, including `blast_radius`, `risk_score` and an optional
  `ai_explanation`.
- `ScanResult` — all findings plus run metadata, with `to_dict()` for the JSON
  schema.

## Design invariants

1. **Deterministic decisions.** Risk is decided by rules, never by an LLM.
2. **Stable rule IDs.** Once released, a rule ID never changes.
3. **Works offline.** The default path needs no network.
4. **Dependency-free models.** The model layer imports nothing beyond the
   standard library, so any component can use it without import cycles.
