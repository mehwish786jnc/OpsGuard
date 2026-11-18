"""Build a dependency graph of infrastructure resources.

Edges point from a **consumer** to the **provider** it depends on::

    Ingress ──▶ Service ──▶ Deployment ──▶ Secret
                                       └──▶ ConfigMap

With this orientation, everything that would be affected by a change to node
``X`` is the set of *ancestors* of ``X`` (nodes that can reach ``X``). This is
exactly the blast radius.

Kubernetes relationships are derived from labels/selectors and references.
Terraform relationships are derived from the plan's resource addresses appearing
in each other's configuration (a lightweight dependency heuristic).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

import networkx as nx

from opsguard.scanner.kubernetes import K8sResource
from opsguard.scanner.terraform import TfResourceChange


@dataclass
class DependencyGraph:
    """Wraps a NetworkX DiGraph with OpsGuard-specific queries."""

    graph: nx.DiGraph

    def dependents_of(self, node_id: str) -> List[str]:
        """All nodes that transitively depend on ``node_id`` (its blast radius)."""
        if node_id not in self.graph:
            return []
        return sorted(nx.ancestors(self.graph, node_id))

    def label(self, node_id: str) -> str:
        data = self.graph.nodes.get(node_id, {})
        return data.get("label", node_id)

    def exists(self, node_id: str) -> bool:
        return node_id in self.graph


def _labels_match(selector: Dict[str, Any], labels: Dict[str, Any]) -> bool:
    if not selector:
        return False
    return all(labels.get(k) == v for k, v in selector.items())


def _pod_labels(resource: K8sResource) -> Dict[str, Any]:
    template = resource.pod_template() or {}
    meta = template.get("metadata", {}) if isinstance(template, dict) else {}
    labels = meta.get("labels", {}) if isinstance(meta, dict) else {}
    return labels if isinstance(labels, dict) else {}


def _referenced_secrets_configmaps(resource: K8sResource) -> Set[tuple]:
    """Return a set of ('Secret'|'ConfigMap', name) referenced by the workload."""
    refs: Set[tuple] = set()
    ps = resource.pod_spec()
    if not ps:
        return refs

    # Volumes
    for vol in ps.get("volumes", []) or []:
        if not isinstance(vol, dict):
            continue
        if isinstance(vol.get("secret"), dict) and vol["secret"].get("secretName"):
            refs.add(("Secret", vol["secret"]["secretName"]))
        if isinstance(vol.get("configMap"), dict) and vol["configMap"].get("name"):
            refs.add(("ConfigMap", vol["configMap"]["name"]))
        projected = vol.get("projected", {})
        if isinstance(projected, dict):
            for src in projected.get("sources", []) or []:
                if isinstance(src, dict):
                    if isinstance(src.get("secret"), dict) and src["secret"].get("name"):
                        refs.add(("Secret", src["secret"]["name"]))
                    if isinstance(src.get("configMap"), dict) and src["configMap"].get("name"):
                        refs.add(("ConfigMap", src["configMap"]["name"]))

    # imagePullSecrets
    for ips in ps.get("imagePullSecrets", []) or []:
        if isinstance(ips, dict) and ips.get("name"):
            refs.add(("Secret", ips["name"]))

    # Container env / envFrom
    for container in resource.containers():
        for ef in container.get("envFrom", []) or []:
            if not isinstance(ef, dict):
                continue
            if isinstance(ef.get("secretRef"), dict) and ef["secretRef"].get("name"):
                refs.add(("Secret", ef["secretRef"]["name"]))
            if isinstance(ef.get("configMapRef"), dict) and ef["configMapRef"].get("name"):
                refs.add(("ConfigMap", ef["configMapRef"]["name"]))
        for env in container.get("env", []) or []:
            if not isinstance(env, dict):
                continue
            vf = env.get("valueFrom", {})
            if not isinstance(vf, dict):
                continue
            if isinstance(vf.get("secretKeyRef"), dict) and vf["secretKeyRef"].get("name"):
                refs.add(("Secret", vf["secretKeyRef"]["name"]))
            if isinstance(vf.get("configMapKeyRef"), dict) and vf["configMapKeyRef"].get("name"):
                refs.add(("ConfigMap", vf["configMapKeyRef"]["name"]))

    return refs


def _ingress_backend_services(resource: K8sResource) -> Set[str]:
    services: Set[str] = set()
    spec = resource.spec()
    # Default backend
    default = spec.get("defaultBackend", {})
    if isinstance(default, dict):
        svc = default.get("service", {})
        if isinstance(svc, dict) and svc.get("name"):
            services.add(svc["name"])
    for rule in spec.get("rules", []) or []:
        if not isinstance(rule, dict):
            continue
        http = rule.get("http", {})
        if not isinstance(http, dict):
            continue
        for path in http.get("paths", []) or []:
            if not isinstance(path, dict):
                continue
            backend = path.get("backend", {})
            if not isinstance(backend, dict):
                continue
            svc = backend.get("service", {})
            if isinstance(svc, dict) and svc.get("name"):
                services.add(svc["name"])
            # Legacy extensions/v1beta1 form
            if backend.get("serviceName"):
                services.add(backend["serviceName"])
    return services


def build_graph(
    k8s_resources: List[K8sResource],
    tf_changes: Optional[List[TfResourceChange]] = None,
) -> DependencyGraph:
    g = nx.DiGraph()
    tf_changes = tf_changes or []

    # --- Register all nodes first -----------------------------------------
    by_kind_name: Dict[tuple, str] = {}
    for r in k8s_resources:
        node_id = r.ref.node_id
        g.add_node(node_id, label=str(r.ref), kind=r.kind, provider="kubernetes")
        ns = r.namespace or "default"
        by_kind_name[(r.kind, ns, r.name)] = node_id

    for change in tf_changes:
        node_id = change.ref.node_id
        g.add_node(node_id, label=change.address, kind=change.type, provider="terraform")

    def _find(kind: str, name: str, namespace: Optional[str]) -> Optional[str]:
        ns = namespace or "default"
        return by_kind_name.get((kind, ns, name))

    # --- Kubernetes edges --------------------------------------------------
    workloads = [
        r
        for r in k8s_resources
        if r.kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod")
    ]

    for r in k8s_resources:
        if r.kind == "Service":
            selector = r.spec().get("selector", {}) or {}
            if not isinstance(selector, dict):
                continue
            for w in workloads:
                if w.namespace == r.namespace and _labels_match(selector, _pod_labels(w)):
                    # Service depends on the workload it routes to.
                    g.add_edge(r.ref.node_id, w.ref.node_id, relation="routes-to")

        elif r.kind == "Ingress":
            for svc_name in _ingress_backend_services(r):
                target = _find("Service", svc_name, r.namespace)
                if target:
                    g.add_edge(r.ref.node_id, target, relation="routes-to")

        if r.kind in (
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "ReplicaSet",
            "Pod",
            "Job",
            "CronJob",
        ):
            for kind, name in _referenced_secrets_configmaps(r):
                target = _find(kind, name, r.namespace)
                if target:
                    g.add_edge(r.ref.node_id, target, relation="mounts")

    # --- Terraform edges (heuristic: address referenced in another config) -
    _link_terraform(g, tf_changes)

    return DependencyGraph(graph=g)


def _link_terraform(g: nx.DiGraph, tf_changes: List[TfResourceChange]) -> None:
    """Connect terraform resources when one references another's address.

    Terraform plan JSON resolves interpolations to concrete values, so we cannot
    always see ``aws_vpc.main.id`` style references. As a pragmatic heuristic we
    look for each resource's address or name appearing as a substring in another
    resource's serialized config.
    """
    serialized: Dict[str, str] = {}
    for change in tf_changes:
        serialized[change.ref.node_id] = json.dumps(change.config(), default=str)

    for consumer in tf_changes:
        blob = serialized.get(consumer.ref.node_id, "")
        for provider in tf_changes:
            if provider.ref.node_id == consumer.ref.node_id:
                continue
            token = f"{provider.type}.{provider.name}"
            if token in blob:
                g.add_edge(consumer.ref.node_id, provider.ref.node_id, relation="references")
