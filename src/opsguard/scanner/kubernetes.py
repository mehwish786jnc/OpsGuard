"""Kubernetes manifest scanner.

Parses one or more YAML files (including multi-document files) into
:class:`K8sResource` objects. The scanner is deliberately tolerant: a malformed
document never aborts the whole scan, it is recorded as an error instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from opsguard.models import ResourceRef

# File extensions we treat as Kubernetes manifests.
_YAML_EXTS = (".yaml", ".yml")

# Terraform plan files often also end in .json; those are handled elsewhere.
# We only look at YAML here.


@dataclass
class K8sResource:
    """A single Kubernetes object parsed from a manifest."""

    kind: str
    name: str
    namespace: Optional[str]
    manifest: Dict[str, Any]
    file: str

    @property
    def ref(self) -> ResourceRef:
        return ResourceRef(
            kind=self.kind,
            name=self.name,
            namespace=self.namespace,
            provider="kubernetes",
            file=self.file,
        )

    @property
    def api_version(self) -> str:
        return str(self.manifest.get("apiVersion", ""))

    def spec(self) -> Dict[str, Any]:
        spec = self.manifest.get("spec")
        return spec if isinstance(spec, dict) else {}

    def pod_template(self) -> Optional[Dict[str, Any]]:
        """Return the pod template spec for workloads, if present.

        Handles Deployment/StatefulSet/DaemonSet/ReplicaSet/Job (``spec.template``)
        and bare Pods (the manifest itself).
        """
        if self.kind == "Pod":
            return self.manifest
        template = self.spec().get("template")
        if isinstance(template, dict):
            return template
        # CronJob nests the template one level deeper.
        if self.kind == "CronJob":
            job = self.spec().get("jobTemplate", {})
            if isinstance(job, dict):
                tmpl = job.get("spec", {}).get("template")
                if isinstance(tmpl, dict):
                    return tmpl
        return None

    def pod_spec(self) -> Dict[str, Any]:
        """Return the PodSpec (the object that holds ``containers``)."""
        if self.kind == "Pod":
            return self.spec()
        template = self.pod_template()
        if not template:
            return {}
        ps = template.get("spec", {})
        return ps if isinstance(ps, dict) else {}

    def containers(self) -> List[Dict[str, Any]]:
        """All containers and initContainers defined on the workload."""
        pod_spec = self.pod_spec()
        if not pod_spec:
            return []
        containers = pod_spec.get("containers", []) or []
        inits = pod_spec.get("initContainers", []) or []
        return [c for c in list(containers) + list(inits) if isinstance(c, dict)]


def _iter_manifest_files(path: str) -> Iterable[str]:
    if os.path.isfile(path):
        if path.lower().endswith(_YAML_EXTS):
            yield path
        return
    for root, _dirs, files in os.walk(path):
        # Skip common noise directories.
        if any(part in root.split(os.sep) for part in (".git", "node_modules", ".terraform")):
            continue
        for name in files:
            if name.lower().endswith(_YAML_EXTS):
                yield os.path.join(root, name)


def _load_documents(file_path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            docs = list(yaml.safe_load_all(handle))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        return [], f"{file_path}: {exc}"
    return [d for d in docs if isinstance(d, dict)], None


def scan_kubernetes(path: str) -> Tuple[List[K8sResource], List[str], List[str]]:
    """Scan ``path`` (file or directory) for Kubernetes resources.

    Returns ``(resources, files_scanned, errors)``.
    """
    resources: List[K8sResource] = []
    files_scanned: List[str] = []
    errors: List[str] = []

    for file_path in _iter_manifest_files(path):
        docs, err = _load_documents(file_path)
        if err:
            errors.append(err)
            continue
        if not docs:
            continue
        # Only count files that actually contained k8s-looking documents.
        counted = False
        for doc in docs:
            kind = doc.get("kind")
            if not kind or "apiVersion" not in doc:
                # Not a Kubernetes manifest (could be CI config, Helm values, etc.)
                continue
            metadata = doc.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
            name = metadata.get("name", "<unnamed>")
            namespace = metadata.get("namespace")
            resources.append(
                K8sResource(
                    kind=str(kind),
                    name=str(name),
                    namespace=namespace,
                    manifest=doc,
                    file=file_path,
                )
            )
            counted = True
        if counted:
            files_scanned.append(file_path)

    return resources, files_scanned, errors
