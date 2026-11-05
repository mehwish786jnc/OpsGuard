"""Annotate findings with their blast radius.

For each finding, we look up the resources that depend on the finding's resource
and attach them. This turns a local issue ("this Secret changed") into an impact
statement ("this Secret changed and 3 services depend on it").
"""

from __future__ import annotations

from typing import List

from opsguard.graph.dependency import DependencyGraph
from opsguard.models import Finding


def annotate_blast_radius(findings: List[Finding], graph: DependencyGraph) -> None:
    """Mutates findings in place, populating ``blast_radius`` and ``affected``."""
    for finding in findings:
        node_id = finding.resource.node_id
        dependents = graph.dependents_of(node_id)
        if not dependents:
            continue
        finding.blast_radius = dependents
        finding.affected = [graph.label(dep) for dep in dependents]
