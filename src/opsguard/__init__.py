"""OpsGuard — production change intelligence.

Catch the change before it breaks production.

OpsGuard analyzes infrastructure changes (Kubernetes manifests and Terraform
plans) to surface risks — public exposure, destructive changes, insecure
configuration, and missing reliability guardrails — *before* they are merged.

Architectural principle:
    Security decisions are made by **deterministic rules**. AI is used only to
    *explain* findings and suggest remediation — never to independently decide
    whether a deployment is safe.
"""

from opsguard.models import (
    Finding,
    ResourceRef,
    ScanResult,
    Severity,
)

__all__ = [
    "Finding",
    "ResourceRef",
    "ScanResult",
    "Severity",
    "__version__",
]

__version__ = "0.1.0"
