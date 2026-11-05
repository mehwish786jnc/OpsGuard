"""Tests for Kubernetes rules."""

from __future__ import annotations

from typing import List

import yaml

from opsguard.models import Finding, Severity
from opsguard.rules import get_kubernetes_rules
from opsguard.scanner.kubernetes import K8sResource


def _resource(manifest_yaml: str) -> K8sResource:
    manifest = yaml.safe_load(manifest_yaml)
    meta = manifest.get("metadata", {})
    return K8sResource(
        kind=manifest["kind"],
        name=meta.get("name", "x"),
        namespace=meta.get("namespace"),
        manifest=manifest,
        file="test.yaml",
    )


def _run_rules(resource: K8sResource) -> List[Finding]:
    findings: List[Finding] = []
    for rule in get_kubernetes_rules():
        if rule.matches(resource):
            findings.extend(rule.evaluate(resource))
    return findings


def _ids(findings: List[Finding]) -> set:
    return {f.rule_id for f in findings}


PRIVILEGED_POD = """
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  hostNetwork: true
  containers:
    - name: c
      image: nginx:latest
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
        capabilities:
          add: [SYS_ADMIN]
"""


def test_privileged_pod_triggers_security_rules():
    findings = _run_rules(_resource(PRIVILEGED_POD))
    ids = _ids(findings)
    assert "K8S-SEC-001" in ids  # privileged
    assert "K8S-SEC-002" in ids  # hostNetwork
    assert "K8S-SEC-004" in ids  # runs as root
    assert "K8S-SEC-005" in ids  # privilege escalation
    assert "K8S-SEC-006" in ids  # dangerous capability
    assert "K8S-IMG-001" in ids  # latest tag


def test_privileged_is_critical():
    findings = _run_rules(_resource(PRIVILEGED_POD))
    priv = [f for f in findings if f.rule_id == "K8S-SEC-001"][0]
    assert priv.severity == Severity.CRITICAL


HARDENED_DEPLOY = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 3
  template:
    metadata:
      labels: {app: api}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      automountServiceAccountToken: false
      containers:
        - name: c
          image: repo/app@sha256:abc123
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          livenessProbe: {httpGet: {path: /, port: 8080}}
          readinessProbe: {httpGet: {path: /, port: 8080}}
          resources:
            requests: {cpu: 100m, memory: 64Mi}
            limits: {cpu: 200m, memory: 128Mi}
"""


def test_hardened_deployment_is_clean():
    findings = _run_rules(_resource(HARDENED_DEPLOY))
    assert findings == [], f"expected no findings, got {_ids(findings)}"


def test_loadbalancer_service_flagged():
    svc = _resource(
        """
apiVersion: v1
kind: Service
metadata: {name: api}
spec:
  type: LoadBalancer
  selector: {app: api}
"""
    )
    assert "K8S-EXPOSURE-001" in _ids(_run_rules(svc))


def test_internal_loadbalancer_not_flagged():
    svc = _resource(
        """
apiVersion: v1
kind: Service
metadata:
  name: api
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
spec:
  type: LoadBalancer
  selector: {app: api}
"""
    )
    assert "K8S-EXPOSURE-001" not in _ids(_run_rules(svc))


def test_single_replica_flagged():
    dep = _resource(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  replicas: 1
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: c
          image: repo/app:1.0.0
          livenessProbe: {httpGet: {path: /, port: 80}}
          readinessProbe: {httpGet: {path: /, port: 80}}
          resources:
            requests: {cpu: 1m, memory: 1Mi}
            limits: {memory: 2Mi}
"""
    )
    assert "K8S-REL-003" in _ids(_run_rules(dep))


def test_ingress_without_tls_flagged():
    ing = _resource(
        """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web}
spec:
  rules:
    - host: x.example.com
"""
    )
    assert "K8S-EXPOSURE-003" in _ids(_run_rules(ing))


def test_pinned_image_not_flagged_as_mutable():
    pod = _resource(
        """
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: repo/app:1.2.3
"""
    )
    assert "K8S-IMG-001" not in _ids(_run_rules(pod))
