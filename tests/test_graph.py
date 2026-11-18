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


def test_dependents_of_unknown_node_is_empty():
    g = build_graph(_resources())
    assert g.dependents_of("k8s:Secret/prod/does-not-exist") == []


def test_label_falls_back_to_node_id():
    g = build_graph(_resources())
    assert g.label("k8s:Deployment/prod/api")  # known node has a label
    assert g.label("missing") == "missing"  # unknown node → id itself


# --------------------------------------------------------------------------- #
# Reference resolution: volumes, projected sources, imagePullSecrets, env.
# --------------------------------------------------------------------------- #

RICH_REFS = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  template:
    metadata: {labels: {app: web}}
    spec:
      imagePullSecrets:
        - name: registry-cred
      volumes:
        - name: v1
          secret: {secretName: tls-secret}
        - name: v2
          configMap: {name: app-config}
        - name: v3
          projected:
            sources:
              - secret: {name: proj-secret}
              - configMap: {name: proj-config}
      containers:
        - name: c
          image: repo/web:1
          env:
            - name: PW
              valueFrom:
                secretKeyRef: {name: env-secret, key: pw}
            - name: CFG
              valueFrom:
                configMapKeyRef: {name: env-config, key: cfg}
---
apiVersion: v1
kind: Secret
metadata: {name: tls-secret, namespace: prod}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: app-config, namespace: prod}
---
apiVersion: v1
kind: Secret
metadata: {name: proj-secret, namespace: prod}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: proj-config, namespace: prod}
---
apiVersion: v1
kind: Secret
metadata: {name: env-secret, namespace: prod}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: env-config, namespace: prod}
---
apiVersion: v1
kind: Secret
metadata: {name: registry-cred, namespace: prod}
"""


def _rich_resources():
    docs = [d for d in yaml.safe_load_all(RICH_REFS) if d]
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


def test_all_reference_kinds_create_edges():
    g = build_graph(_rich_resources())
    dep = "k8s:Deployment/prod/web"
    for target in (
        "k8s:Secret/prod/tls-secret",
        "k8s:ConfigMap/prod/app-config",
        "k8s:Secret/prod/proj-secret",
        "k8s:ConfigMap/prod/proj-config",
        "k8s:Secret/prod/env-secret",
        "k8s:ConfigMap/prod/env-config",
        "k8s:Secret/prod/registry-cred",
    ):
        assert g.graph.has_edge(dep, target), f"missing edge to {target}"


# --------------------------------------------------------------------------- #
# Ingress default backend + legacy serviceName form.
# --------------------------------------------------------------------------- #

LEGACY_INGRESS = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: prod}
spec:
  template:
    metadata: {labels: {app: api}}
    spec:
      containers: [{name: c, image: repo/api:1}]
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: prod}
spec:
  selector: {app: api}
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata: {name: legacy, namespace: prod}
spec:
  defaultBackend:
    service: {name: api}
  rules:
    - http:
        paths:
          - backend: {serviceName: api}
"""


def test_ingress_default_backend_and_legacy_service_name():
    docs = [d for d in yaml.safe_load_all(LEGACY_INGRESS) if d]
    resources = [
        K8sResource(
            kind=d["kind"],
            name=d["metadata"]["name"],
            namespace=d["metadata"].get("namespace"),
            manifest=d,
            file="m.yaml",
        )
        for d in docs
    ]
    g = build_graph(resources)
    assert g.graph.has_edge("k8s:Ingress/prod/legacy", "k8s:Service/prod/api")


# --------------------------------------------------------------------------- #
# Terraform reference linking (address substring heuristic).
# --------------------------------------------------------------------------- #


def test_terraform_reference_edge():
    from opsguard.scanner.terraform import TfResourceChange

    vpc = TfResourceChange(
        address="aws_vpc.main",
        type="aws_vpc",
        name="main",
        actions=["create"],
        before=None,
        after={"cidr_block": "10.0.0.0/16"},
    )
    subnet = TfResourceChange(
        address="aws_subnet.app",
        type="aws_subnet",
        name="app",
        actions=["create"],
        before=None,
        # References the vpc's address token in its serialized config.
        after={"vpc_id": "aws_vpc.main"},
    )
    g = build_graph([], [vpc, subnet])
    assert g.graph.has_edge("tf:aws_subnet.app", "tf:aws_vpc.main")
