"""Risk scoring.

Produces a composite 0-100 risk score for each finding by combining:

* the **deterministic severity** assigned by the rule (dominant factor),
* the **blast radius** (how many resources depend on the affected one),
* the **change type** (destroy/replace is riskier than create/update).

The severity is always the source of truth for pass/fail gating. The score is a
secondary signal used for ordering and prioritisation.
"""

from __future__ import annotations

from typing import List

from opsguard.models import ChangeAction, Finding, Severity

_SEVERITY_BASE = {
    Severity.INFO: 5,
    Severity.LOW: 20,
    Severity.MEDIUM: 45,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}

_DESTRUCTIVE = {ChangeAction.DELETE, ChangeAction.REPLACE}


def score_finding(finding: Finding) -> int:
    base = _SEVERITY_BASE.get(finding.severity, 40)

    # Blast radius: each dependent adds weight, capped so a single HIGH with a
    # huge fan-out never silently overtakes a CRITICAL.
    blast = len(finding.blast_radius)
    blast_bonus = min(blast * 3, 10)

    change_bonus = 5 if finding.change in _DESTRUCTIVE else 0

    return int(max(0, min(100, base + blast_bonus + change_bonus)))


def score_findings(findings: List[Finding]) -> None:
    """Populate ``risk_score`` on each finding in place."""
    for finding in findings:
        finding.risk_score = score_finding(finding)
