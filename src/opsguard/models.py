"""Core data models shared across OpsGuard.

These are intentionally dependency-free (standard library only) so the model
layer can be imported by any component — scanners, rules, graph, risk, report
and the CLI — without creating import cycles.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.IntEnum):
    """Ordered severity levels.

    Implemented as an ``IntEnum`` so findings can be compared and sorted by
    severity directly (``CRITICAL > HIGH > ...``).
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "str | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            valid = ", ".join(s.name for s in cls)
            raise ValueError(f"Unknown severity '{value}'. Expected one of: {valid}") from exc

    @property
    def label(self) -> str:
        return self.name.capitalize()


class ChangeAction(str, enum.Enum):
    """The kind of change a resource is undergoing.

    Derived from a Terraform plan (``create``/``update``/``delete``/``replace``)
    or inferred for Kubernetes manifests (``present`` when no baseline exists).
    """

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"
    NOOP = "no-op"
    PRESENT = "present"


@dataclass(frozen=True)
class ResourceRef:
    """A stable, human-readable reference to an infrastructure resource."""

    kind: str
    name: str
    namespace: Optional[str] = None
    provider: str = "kubernetes"  # "kubernetes" | "terraform"
    file: Optional[str] = None

    @property
    def node_id(self) -> str:
        """A unique identifier used as the dependency-graph node key."""
        if self.provider == "kubernetes":
            ns = self.namespace or "default"
            return f"k8s:{self.kind}/{ns}/{self.name}"
        return f"tf:{self.kind}.{self.name}"

    def __str__(self) -> str:
        if self.namespace:
            return f"{self.kind}/{self.name} (ns={self.namespace})"
        return f"{self.kind}/{self.name}"


@dataclass
class Finding:
    """A single risk detected by a deterministic rule."""

    rule_id: str
    title: str
    severity: Severity
    resource: ResourceRef
    message: str
    impact: str = ""
    remediation: str = ""
    change: ChangeAction = ChangeAction.PRESENT
    evidence: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    # Populated by the blast-radius analysis: node_ids of dependent resources.
    blast_radius: List[str] = field(default_factory=list)
    # Human readable blast-radius descriptions, populated alongside blast_radius.
    affected: List[str] = field(default_factory=list)
    # Optional AI-generated explanation (deterministic fallback by default).
    ai_explanation: Optional[str] = None
    # Composite risk score 0-100, set by the risk engine.
    risk_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["change"] = self.change.value
        data["resource"] = {
            "kind": self.resource.kind,
            "name": self.resource.name,
            "namespace": self.resource.namespace,
            "provider": self.resource.provider,
            "file": self.resource.file,
            "node_id": self.resource.node_id,
        }
        return data


@dataclass
class ScanResult:
    """The outcome of a scan: all findings plus run metadata."""

    findings: List[Finding] = field(default_factory=list)
    resources_scanned: int = 0
    files_scanned: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    def sorted_findings(self) -> List[Finding]:
        """Findings ordered by risk score then severity (most severe first)."""
        return sorted(
            self.findings,
            key=lambda f: (f.risk_score, int(f.severity)),
            reverse=True,
        )

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return counts

    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_findings": len(self.findings),
                "resources_scanned": self.resources_scanned,
                "files_scanned": len(self.files_scanned),
                "counts_by_severity": self.counts_by_severity(),
                "max_severity": self.max_severity().name if self.max_severity() else None,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
        }
