"""Kubernetes manifest scanner.

Parses one or more YAML files (including multi-document files) into
:class:`K8sResource` objects. The scanner is deliberately tolerant: a malformed
document never aborts the whole scan, it is recorded as an error instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml

from opsguard.models import ResourceRef
from opsguard.scanner.render import (
    is_helm_chart,
    is_render_root,
    render_helm,
    render_kustomize,
)

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


def _parse_documents(text: str, source: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse a multi-document YAML string into dict documents."""
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        return [], f"{source}: {exc}"
    return [d for d in docs if isinstance(d, dict)], None


def _load_documents(file_path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        return [], f"{file_path}: {exc}"
    return _parse_documents(text, file_path)


def _docs_to_resources(docs: List[Dict[str, Any]], source: str) -> List[K8sResource]:
    """Turn parsed YAML documents into :class:`K8sResource` objects.

    Documents that are not Kubernetes manifests (no ``kind``/``apiVersion``) are
    skipped — they could be CI config, Helm values, etc.
    """
    resources: List[K8sResource] = []
    for doc in docs:
        kind = doc.get("kind")
        if not kind or "apiVersion" not in doc:
            continue
        metadata = doc.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        resources.append(
            K8sResource(
                kind=str(kind),
                name=str(metadata.get("name", "<unnamed>")),
                namespace=metadata.get("namespace"),
                manifest=doc,
                file=source,
            )
        )
    return resources


def _render_root(
    path: str,
    helm_values: Optional[List[str]],
    resources: List[K8sResource],
    files_scanned: List[str],
    errors: List[str],
) -> None:
    """Render a Helm chart or Kustomize overlay and collect its resources."""
    if is_helm_chart(path):
        text, err = render_helm(path, helm_values)
        label = f"{path} (helm)"
    else:
        text, err = render_kustomize(path)
        label = f"{path} (kustomize)"
    if err:
        errors.append(err)
        return
    docs, perr = _parse_documents(text, label)
    if perr:
        errors.append(perr)
        return
    res = _docs_to_resources(docs, label)
    if res:
        resources.extend(res)
        files_scanned.append(label)


def _scan_file(
    file_path: str,
    resources: List[K8sResource],
    files_scanned: List[str],
    errors: List[str],
) -> None:
    docs, err = _load_documents(file_path)
    if err:
        errors.append(err)
        return
    res = _docs_to_resources(docs, file_path)
    if res:
        resources.extend(res)
        files_scanned.append(file_path)


def _prune_render_roots(
    root: str,
    dirs: List[str],
    render: bool,
    helm_values: Optional[List[str]],
    resources: List[K8sResource],
    files_scanned: List[str],
    errors: List[str],
) -> None:
    """Render (or skip) render-root subdirectories and prune them from ``dirs``.

    Mutates ``dirs`` in place so ``os.walk`` does not descend into a chart or
    overlay and mis-parse its template files as raw YAML.
    """
    remaining = []
    for d in sorted(dirs):
        sub = os.path.join(root, d)
        if is_render_root(sub):
            if render:
                _render_root(sub, helm_values, resources, files_scanned, errors)
        else:
            remaining.append(d)
    dirs[:] = remaining


def _walk_directory(
    path: str,
    render: bool,
    helm_values: Optional[List[str]],
    resources: List[K8sResource],
    files_scanned: List[str],
    errors: List[str],
) -> None:
    """Walk a directory tree for raw YAML, rendering/pruning render roots."""
    for root, dirs, files in os.walk(path):
        parts = root.split(os.sep)
        if any(part in parts for part in (".git", "node_modules", ".terraform")):
            dirs[:] = []
            continue
        _prune_render_roots(root, dirs, render, helm_values, resources, files_scanned, errors)
        for name in files:
            if name.lower().endswith(_YAML_EXTS):
                _scan_file(os.path.join(root, name), resources, files_scanned, errors)


def scan_kubernetes(
    path: str,
    *,
    render: bool = True,
    helm_values: Optional[List[str]] = None,
) -> Tuple[List[K8sResource], List[str], List[str]]:
    """Scan ``path`` (file or directory) for Kubernetes resources.

    When ``render`` is true, Helm charts (``Chart.yaml``) and Kustomize overlays
    (``kustomization.yaml``) encountered under ``path`` are rendered to plain
    manifests first, then scanned. Render roots are never walked as raw YAML, so
    Go-template files are not mis-parsed. With ``render`` false, render roots are
    skipped entirely and only raw YAML is scanned.

    Returns ``(resources, files_scanned, errors)``.
    """
    resources: List[K8sResource] = []
    files_scanned: List[str] = []
    errors: List[str] = []

    if os.path.isfile(path):
        if path.lower().endswith(_YAML_EXTS):
            _scan_file(path, resources, files_scanned, errors)
    elif is_render_root(path):
        # The path itself is a chart/overlay root.
        if render:
            _render_root(path, helm_values, resources, files_scanned, errors)
    elif os.path.isdir(path):
        _walk_directory(path, render, helm_values, resources, files_scanned, errors)

    return resources, files_scanned, errors
