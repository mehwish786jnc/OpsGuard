# OpsGuard Roadmap

OpsGuard follows a milestone-based roadmap. Milestones M1–M4 shipped in the
`0.1.0` release; the items below the line are what we're building next.

Have an idea or want to pick something up? Open a
[feature request](https://github.com/mehwish786jnc/OpsGuard/issues/new/choose)
or read [CONTRIBUTING.md](CONTRIBUTING.md) — new rules are the single most
valuable contribution.

## Shipped

- [x] **M1 — Infrastructure scanner:** Kubernetes YAML + Terraform plan parsing & rules
- [x] **M2 — Dependency graph:** blast-radius across deployments / services / secrets
- [x] **M3 — Risk intelligence:** severity, scoring, AI explanations
- [x] **M4 — Open-source release:** GitHub Action, PR reports, SARIF, docs
- [x] **Helm & Kustomize rendering:** scan templated manifests, not just raw YAML

## Planned

- [ ] **OPA / Rego custom policies** — bring-your-own policy alongside built-in rules
- [ ] **Scanner enrichment** — optional Trivy / Checkov / KubeLinter integration
- [ ] **Kubernetes baseline diffing** — detect removed env vars / secrets a workload depends on
- [ ] **More CI integrations** — GitLab CI and Bitbucket Pipelines, alongside GitHub Actions

## Design principles (won't change)

1. **Deterministic decisions.** Whether a change is risky is decided by rules,
   never by an LLM. AI only *explains*.
2. **Stable rule IDs.** Once released, a rule ID never changes — people suppress
   findings by ID.
3. **Works offline.** The default path needs no network, so OpsGuard runs in
   air-gapped CI.
