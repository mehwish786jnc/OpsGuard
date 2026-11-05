"""Scanners turn raw infrastructure files into normalized resource objects."""

from opsguard.scanner.kubernetes import K8sResource, scan_kubernetes
from opsguard.scanner.terraform import TfResourceChange, scan_terraform_plan

__all__ = [
    "K8sResource",
    "scan_kubernetes",
    "TfResourceChange",
    "scan_terraform_plan",
]
