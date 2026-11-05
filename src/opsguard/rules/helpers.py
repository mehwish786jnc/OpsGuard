"""Small helpers shared by Kubernetes rules."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from opsguard.scanner.kubernetes import K8sResource

WORKLOAD_KINDS = (
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
    "Pod",
)


def effective_security_context(resource: K8sResource, container: Dict[str, Any]) -> Dict[str, Any]:
    """Merge pod-level and container-level securityContext.

    Container-level settings win over pod-level ones (matching Kubernetes).
    """
    pod_sc = resource.pod_spec().get("securityContext", {}) or {}
    cont_sc = container.get("securityContext", {}) or {}
    merged: Dict[str, Any] = {}
    if isinstance(pod_sc, dict):
        merged.update(pod_sc)
    if isinstance(cont_sc, dict):
        merged.update(cont_sc)
    return merged


def container_name(container: Dict[str, Any]) -> str:
    return str(container.get("name", "<container>"))


def image_tag(image: str) -> Optional[str]:
    """Extract the tag from an image reference, ignoring the registry port.

    ``registry:5000/app:1.2.3`` -> ``1.2.3``
    ``app`` -> ``None``
    ``app@sha256:...`` -> digest is treated as pinned (returns the digest).
    """
    if "@" in image:
        return image.split("@", 1)[1]
    # Strip any registry host:port by only looking after the last '/'.
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        return last.split(":", 1)[1]
    return None


def is_pinned_image(image: str) -> bool:
    tag = image_tag(image)
    if tag is None:
        return False
    if tag.startswith("sha256:"):
        return True
    return tag not in ("latest", "") and not tag.endswith("-latest")


def has_probe(container: Dict[str, Any], probe: str) -> bool:
    val = container.get(probe)
    return isinstance(val, dict) and len(val) > 0


def exposed_ports(container: Dict[str, Any]) -> List[int]:
    ports = []
    for p in container.get("ports", []) or []:
        if isinstance(p, dict) and "containerPort" in p:
            try:
                ports.append(int(p["containerPort"]))
            except (TypeError, ValueError):
                continue
    return ports
