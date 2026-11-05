"""Kubernetes deterministic rules.

Each rule detects one production risk. Severity reflects potential blast radius
and exploitability. Rules return concrete, actionable remediation.
"""

from __future__ import annotations

from typing import List

from opsguard.models import Finding, Severity
from opsguard.rules.base import KubernetesRule, register
from opsguard.rules.helpers import (
    WORKLOAD_KINDS,
    container_name,
    effective_security_context,
    has_probe,
    is_pinned_image,
)
from opsguard.scanner.kubernetes import K8sResource

# --------------------------------------------------------------------------- #
# Public exposure
# --------------------------------------------------------------------------- #


@register
class ServiceLoadBalancer(KubernetesRule):
    id = "K8S-EXPOSURE-001"
    title = "Service exposed to the internet via LoadBalancer"
    severity = Severity.HIGH
    applies_to = ("Service",)
    references = [
        "https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer",
    ]

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        spec = resource.spec()
        if spec.get("type") != "LoadBalancer":
            return []
        internal = resource.manifest.get("metadata", {}).get("annotations", {}) or {}
        # Common annotations that keep an LB internal.
        internal_markers = (
            "service.beta.kubernetes.io/aws-load-balancer-internal",
            "networking.gke.io/load-balancer-type",
            "service.beta.kubernetes.io/azure-load-balancer-internal",
        )
        if any(k in internal for k in internal_markers):
            return []
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                resource=resource.ref,
                message=(
                    f"Service '{resource.name}' uses type LoadBalancer with no internal-only "
                    "annotation, which provisions a public cloud load balancer."
                ),
                impact=(
                    "Any workload behind this Service becomes reachable from the public "
                    "internet, expanding the attack surface."
                ),
                remediation=(
                    "If the service is internal, use type ClusterIP, or add the cloud "
                    "provider's internal load-balancer annotation. Expose externally only "
                    "through a reviewed Ingress with authentication and TLS."
                ),
                references=self.references,
            )
        ]


@register
class ServiceNodePort(KubernetesRule):
    id = "K8S-EXPOSURE-002"
    title = "Service exposed via NodePort"
    severity = Severity.MEDIUM
    applies_to = ("Service",)

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        if resource.spec().get("type") != "NodePort":
            return []
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                resource=resource.ref,
                message=(
                    f"Service '{resource.name}' uses type NodePort, opening a port on every "
                    "node in the cluster."
                ),
                impact=(
                    "NodePorts bypass Ingress controls and can expose the service on node "
                    "public IPs depending on firewall configuration."
                ),
                remediation=(
                    "Prefer ClusterIP + Ingress. Use NodePort only for controlled, "
                    "firewalled environments."
                ),
            )
        ]


@register
class IngressWithoutTLS(KubernetesRule):
    id = "K8S-EXPOSURE-003"
    title = "Ingress without TLS"
    severity = Severity.MEDIUM
    applies_to = ("Ingress",)

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        spec = resource.spec()
        if spec.get("tls"):
            return []
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                resource=resource.ref,
                message=f"Ingress '{resource.name}' does not define a 'tls' block.",
                impact="Traffic may be served over plaintext HTTP, exposing credentials and data in transit.",
                remediation="Add a 'spec.tls' section and terminate TLS (e.g. via cert-manager).",
            )
        ]


# --------------------------------------------------------------------------- #
# Security context
# --------------------------------------------------------------------------- #


@register
class PrivilegedContainer(KubernetesRule):
    id = "K8S-SEC-001"
    title = "Privileged container"
    severity = Severity.CRITICAL
    applies_to = WORKLOAD_KINDS
    references = ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        findings = []
        for c in resource.containers():
            sc = effective_security_context(resource, c)
            if sc.get("privileged") is True:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        resource=resource.ref,
                        message=f"Container '{container_name(c)}' runs in privileged mode.",
                        impact=(
                            "A privileged container has nearly unrestricted access to the host "
                            "kernel and devices; a compromise can lead to full node takeover."
                        ),
                        remediation=(
                            "Remove 'securityContext.privileged: true'. Grant only the specific "
                            "Linux capabilities the workload needs."
                        ),
                        evidence={"container": container_name(c)},
                        references=self.references,
                    )
                )
        return findings


@register
class HostNetwork(KubernetesRule):
    id = "K8S-SEC-002"
    title = "Pod uses host network namespace"
    severity = Severity.HIGH
    applies_to = WORKLOAD_KINDS

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        if resource.pod_spec().get("hostNetwork") is True:
            return [
                Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    resource=resource.ref,
                    message=f"Workload '{resource.name}' sets hostNetwork: true.",
                    impact="The pod shares the node's network stack, bypassing NetworkPolicies and exposing host interfaces.",
                    remediation="Remove 'hostNetwork: true' unless building a node-level agent that genuinely needs it.",
                )
            ]
        return []


@register
class HostPIDOrIPC(KubernetesRule):
    id = "K8S-SEC-003"
    title = "Pod shares host PID or IPC namespace"
    severity = Severity.HIGH
    applies_to = WORKLOAD_KINDS

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        ps = resource.pod_spec()
        shared = [k for k in ("hostPID", "hostIPC") if ps.get(k) is True]
        if not shared:
            return []
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                resource=resource.ref,
                message=f"Workload '{resource.name}' sets {', '.join(shared)}: true.",
                impact="Sharing host PID/IPC lets the container inspect and signal other processes on the node.",
                remediation=f"Remove {', '.join(shared)} unless strictly required.",
            )
        ]


@register
class RunAsRoot(KubernetesRule):
    id = "K8S-SEC-004"
    title = "Container may run as root"
    severity = Severity.HIGH
    applies_to = WORKLOAD_KINDS

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        findings = []
        for c in resource.containers():
            sc = effective_security_context(resource, c)
            run_as_non_root = sc.get("runAsNonRoot")
            run_as_user = sc.get("runAsUser")
            runs_as_root = run_as_user == 0
            not_guarded = run_as_non_root is not True and run_as_user is None
            if runs_as_root or not_guarded:
                reason = (
                    "runAsUser is 0 (root)"
                    if runs_as_root
                    else "neither runAsNonRoot nor a non-zero runAsUser is set"
                )
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity if runs_as_root else Severity.MEDIUM,
                        resource=resource.ref,
                        message=f"Container '{container_name(c)}' may run as root ({reason}).",
                        impact="Running as root increases the impact of a container escape or application compromise.",
                        remediation="Set 'securityContext.runAsNonRoot: true' and a non-zero 'runAsUser'.",
                        evidence={"container": container_name(c)},
                    )
                )
        return findings


@register
class PrivilegeEscalation(KubernetesRule):
    id = "K8S-SEC-005"
    title = "Privilege escalation not disabled"
    severity = Severity.MEDIUM
    applies_to = WORKLOAD_KINDS

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        findings = []
        for c in resource.containers():
            sc = effective_security_context(resource, c)
            if sc.get("allowPrivilegeEscalation") is not False:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        resource=resource.ref,
                        message=(
                            f"Container '{container_name(c)}' does not set "
                            "allowPrivilegeEscalation: false."
                        ),
                        impact="A process could gain more privileges than its parent (e.g. via setuid binaries).",
                        remediation="Set 'securityContext.allowPrivilegeEscalation: false'.",
                        evidence={"container": container_name(c)},
                    )
                )
        return findings


@register
class DangerousCapabilities(KubernetesRule):
    id = "K8S-SEC-006"
    title = "Dangerous Linux capability added"
    severity = Severity.HIGH
    applies_to = WORKLOAD_KINDS

    _DANGEROUS = {
        "ALL",
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_OVERRIDE",
        "SYS_RAWIO",
    }

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        findings = []
        for c in resource.containers():
            sc = effective_security_context(resource, c)
            caps = (sc.get("capabilities", {}) or {}).get("add", []) or []
            dangerous = sorted({str(x).upper() for x in caps} & self._DANGEROUS)
            if dangerous:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        resource=resource.ref,
                        message=(
                            f"Container '{container_name(c)}' adds dangerous "
                            f"capabilities: {', '.join(dangerous)}."
                        ),
                        impact="Powerful capabilities can be abused to escalate to the host.",
                        remediation="Drop all capabilities ('capabilities.drop: [ALL]') and add back only what is required.",
                        evidence={"container": container_name(c), "capabilities": dangerous},
                    )
                )
        return findings


@register
class ServiceAccountTokenAutomount(KubernetesRule):
    id = "K8S-SEC-007"
    title = "Service account token auto-mounted"
    severity = Severity.LOW
    applies_to = WORKLOAD_KINDS

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        ps = resource.pod_spec()
        if ps.get("automountServiceAccountToken") is False:
            return []
        # Only flag if the workload exposes a service port (likely reachable).
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                resource=resource.ref,
                message=(
                    f"Workload '{resource.name}' does not disable "
                    "automountServiceAccountToken."
                ),
                impact="A compromised container can use the mounted token to call the Kubernetes API.",
                remediation="Set 'automountServiceAccountToken: false' unless the pod needs API access.",
            )
        ]


# --------------------------------------------------------------------------- #
# Reliability
# --------------------------------------------------------------------------- #


@register
class MissingProbes(KubernetesRule):
    id = "K8S-REL-001"
    title = "Missing liveness/readiness probe"
    severity = Severity.MEDIUM
    applies_to = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet")

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        findings = []
        for c in resource.containers():
            missing = [
                p.replace("Probe", "")
                for p in ("livenessProbe", "readinessProbe")
                if not has_probe(c, p)
            ]
            if missing:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        resource=resource.ref,
                        message=(
                            f"Container '{container_name(c)}' is missing: "
                            f"{', '.join(m + 'Probe' for m in missing)}."
                        ),
                        impact=(
                            "Without probes, Kubernetes cannot detect unhealthy pods or delay "
                            "traffic until the app is ready, causing failed requests during rollout."
                        ),
                        remediation="Define livenessProbe and readinessProbe for each container.",
                        evidence={"container": container_name(c), "missing": missing},
                    )
                )
        return findings


@register
class MissingResourceLimits(KubernetesRule):
    id = "K8S-REL-002"
    title = "Missing resource requests/limits"
    severity = Severity.MEDIUM
    applies_to = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod", "Job", "CronJob")

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        findings = []
        for c in resource.containers():
            res = c.get("resources", {}) or {}
            limits = res.get("limits", {}) or {}
            requests = res.get("requests", {}) or {}
            problems = []
            if not limits.get("memory"):
                problems.append("memory limit")
            if not requests.get("cpu") and not limits.get("cpu"):
                problems.append("cpu request/limit")
            if not requests.get("memory"):
                problems.append("memory request")
            if problems:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity if "memory limit" in problems else Severity.LOW,
                        resource=resource.ref,
                        message=(
                            f"Container '{container_name(c)}' is missing: {', '.join(problems)}."
                        ),
                        impact=(
                            "Without a memory limit a single pod can consume all node memory and "
                            "trigger OOM kills on co-located workloads (noisy neighbour)."
                        ),
                        remediation="Set 'resources.requests' and 'resources.limits' for cpu and memory.",
                        evidence={"container": container_name(c), "missing": problems},
                    )
                )
        return findings


@register
class SingleReplica(KubernetesRule):
    id = "K8S-REL-003"
    title = "Single replica — no redundancy"
    severity = Severity.MEDIUM
    applies_to = ("Deployment",)

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        spec = resource.spec()
        # replicas unset defaults to 1.
        replicas = spec.get("replicas", 1)
        try:
            replicas = int(replicas)
        except (TypeError, ValueError):
            return []
        if replicas >= 2:
            return []
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                resource=resource.ref,
                message=f"Deployment '{resource.name}' runs with {replicas} replica.",
                impact=(
                    "A single replica means any node failure, eviction or rollout causes "
                    "downtime for this service."
                ),
                remediation="Run at least 2 replicas and add a PodDisruptionBudget for critical services.",
                evidence={"replicas": replicas},
            )
        ]


# --------------------------------------------------------------------------- #
# Images
# --------------------------------------------------------------------------- #


@register
class MutableImageTag(KubernetesRule):
    id = "K8S-IMG-001"
    title = "Unpinned or 'latest' image tag"
    severity = Severity.MEDIUM
    applies_to = WORKLOAD_KINDS

    def evaluate(self, resource: K8sResource) -> List[Finding]:
        findings = []
        for c in resource.containers():
            image = str(c.get("image", ""))
            if not image or is_pinned_image(image):
                continue
            findings.append(
                Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    resource=resource.ref,
                    message=(
                        f"Container '{container_name(c)}' uses an unpinned image: '{image}'."
                    ),
                    impact=(
                        "A mutable tag like 'latest' makes rollouts non-reproducible and can pull "
                        "an unreviewed image, including one with new vulnerabilities."
                    ),
                    remediation="Pin images to an immutable tag or digest (e.g. 'app:1.4.2' or 'app@sha256:...').",
                    evidence={"container": container_name(c), "image": image},
                )
            )
        return findings
