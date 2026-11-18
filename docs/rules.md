# Rules

OpsGuard ships **19 deterministic rules**. Run `opsguard rules` to list them
with their current severities. Every rule is pure: the same input always
produces the same findings — no network, no LLM, no randomness.

## Kubernetes

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

## Terraform

| ID | Severity | Detects |
|---|---|---|
| `TF-DESTROY-001` | Critical | Destroy/replace of a stateful resource |
| `TF-NET-001` | High | Security group open to the internet |
| `TF-S3-001` | High/Critical | Public S3 bucket |
| `TF-RDS-001` | High | Publicly accessible database |
| `TF-IAM-001` | High/Critical | Wildcard IAM permissions |

!!! note "About `TF-RDS-002`"
    The `TF-RDS-001` rule also emits a `TF-RDS-002` finding (Medium) when a
    database sets `storage_encrypted = false`. That's why `opsguard rules`
    counts **19 rule classes** while reports may show both IDs.

## Suppressing a rule

Disable a rule by id for a single scan:

```bash
opsguard scan ./k8s --disable K8S-IMG-001 --disable K8S-SEC-007
```

## Writing a new rule

A new rule is the single most valuable contribution you can make — and it's a
few lines of Python. See [Contributing](contributing.md).
