"""Tests for the dependency graph and blast-radius propagation."""

from __future__ import annotations

import yaml

from opsguard.graph import annotate_blast_radius, build_graph
from opsguard.models import Finding, ResourceRef, Severity
from opsguard.scanner.kubernetes import K8sResource

MANIFESTS = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: prod}
spec:
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: c
          image: repo/app:1
          envFrom:
            - secretRef: {name: db-creds}
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: prod}
spec:
  selector: {app: api}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: api, namespace: prod}
spec:
  rules:
    - http:
        paths:
          - backend:
              service: {name: api}
---
apiVersion: v1
kind: Secret
metadata: {name: db-creds, namespace: prod}
"""


def _resources():
    docs = [d for d in yaml.safe_load_all(MANIFESTS) if d]
    out = []
    for d in docs:
        meta = d["metadata"]
        out.append(
            K8sResource(
                kind=d["kind"],
                name=meta["name"],
                namespace=meta.get("namespace"),
                manifest=d,
                file="m.yaml",
            )
        )
    return out


def test_graph_edges_built():
    g = build_graph(_resources())
    assert g.exists("k8s:Deployment/prod/api")
    assert g.exists("k8s:Secret/prod/db-creds")
    # Service routes to Deployment, Ingress routes to Service, Deployment mounts Secret.
    assert g.graph.has_edge("k8s:Service/prod/api", "k8s:Deployment/prod/api")
    assert g.graph.has_edge("k8s:Ingress/prod/api", "k8s:Service/prod/api")
    assert g.graph.has_edge("k8s:Deployment/prod/api", "k8s:Secret/prod/db-creds")


def test_blast_radius_of_secret_includes_everything():
    g = build_graph(_resources())
    dependents = g.dependents_of("k8s:Secret/prod/db-creds")
    assert set(dependents) == {
        "k8s:Deployment/prod/api",
        "k8s:Service/prod/api",
        "k8s:Ingress/prod/api",
    }


def test_blast_radius_of_deployment():
    g = build_graph(_resources())
    dependents = g.dependents_of("k8s:Deployment/prod/api")
    assert set(dependents) == {"k8s:Service/prod/api", "k8s:Ingress/prod/api"}


def test_annotate_blast_radius_populates_finding():
    g = build_graph(_resources())
    finding = Finding(
        rule_id="X",
        title="t",
        severity=Severity.HIGH,
        resource=ResourceRef(kind="Secret", name="db-creds", namespace="prod"),
        message="m",
    )
    annotate_blast_radius([finding], g)
    assert len(finding.blast_radius) == 3
    assert finding.affected  # human-readable labels present
