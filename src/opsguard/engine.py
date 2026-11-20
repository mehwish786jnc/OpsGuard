"""The OpsGuard analysis engine.

Pipeline::

    parse  ─▶  build dependency graph  ─▶  run deterministic rules
           ─▶  annotate blast radius   ─▶  score risk
           ─▶  (optional) AI explanations

Security decisions come entirely from the deterministic rules. The graph, score
and AI layers only enrich findings — they never create or suppress a risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set

from opsguard import rules as rules_pkg
from opsguard.ai import explain_findings
from opsguard.graph import annotate_blast_radius, build_graph
from opsguard.models import ScanResult, Severity
from opsguard.risk import score_findings
from opsguard.scanner import scan_kubernetes, scan_terraform_plan


@dataclass
class ScanConfig:
    """Options controlling a scan."""

    paths: List[str] = field(default_factory=list)
    tf_plans: List[str] = field(default_factory=list)
    disabled_rules: Set[str] = field(default_factory=set)
    min_severity: Severity = Severity.INFO
    render: bool = True
    helm_values: List[str] = field(default_factory=list)
    with_ai: bool = False
    ai_provider: str = "offline"
    ai_model: Optional[str] = None


def analyze(config: ScanConfig) -> ScanResult:
    result = ScanResult()

    # --- Parse -------------------------------------------------------------
    all_k8s = []
    for path in config.paths:
        resources, files, errors = scan_kubernetes(
            path, render=config.render, helm_values=config.helm_values
        )
        all_k8s.extend(resources)
        result.files_scanned.extend(files)
        result.errors.extend(errors)

    all_tf = []
    for plan in config.tf_plans:
        changes, errors = scan_terraform_plan(plan)
        all_tf.extend(changes)
        if plan not in result.files_scanned:
            result.files_scanned.append(plan)
        result.errors.extend(errors)

    result.resources_scanned = len(all_k8s) + len(all_tf)

    # --- Dependency graph --------------------------------------------------
    graph = build_graph(all_k8s, all_tf)

    # --- Deterministic rules ----------------------------------------------
    for rule in rules_pkg.get_kubernetes_rules(config.disabled_rules):
        for resource in all_k8s:
            if rule.matches(resource):
                result.extend(rule.evaluate(resource))

    for tf_rule in rules_pkg.get_terraform_rules(config.disabled_rules):
        for change in all_tf:
            if tf_rule.matches(change):
                result.extend(tf_rule.evaluate(change))

    # --- Enrich ------------------------------------------------------------
    annotate_blast_radius(result.findings, graph)
    score_findings(result.findings)

    if config.with_ai:
        explain_findings(result.findings, provider=config.ai_provider, model=config.ai_model)

    # --- Filter by minimum severity ---------------------------------------
    if config.min_severity > Severity.INFO:
        result.findings = [f for f in result.findings if f.severity >= config.min_severity]

    return result
