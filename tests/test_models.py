"""Tests for the core data models."""

from __future__ import annotations

import pytest

from opsguard.models import (
    ChangeAction,
    Finding,
    ResourceRef,
    ScanResult,
    Severity,
)


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


@pytest.mark.parametrize(
    "value,expected",
    [
        ("critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        (" medium ", Severity.MEDIUM),
        (Severity.LOW, Severity.LOW),
    ],
)
def test_severity_parse(value, expected):
    assert Severity.parse(value) == expected


def test_severity_parse_invalid():
    with pytest.raises(ValueError):
        Severity.parse("nope")


def test_resource_ref_node_id_kubernetes():
    ref = ResourceRef(kind="Deployment", name="api", namespace="prod")
    assert ref.node_id == "k8s:Deployment/prod/api"


def test_resource_ref_node_id_default_namespace():
    ref = ResourceRef(kind="Service", name="api")
    assert ref.node_id == "k8s:Service/default/api"


def test_resource_ref_node_id_terraform():
    ref = ResourceRef(kind="aws_db_instance", name="db", provider="terraform")
    assert ref.node_id == "tf:aws_db_instance.db"


def _finding(sev: Severity, score: int = 0) -> Finding:
    return Finding(
        rule_id="X-1",
        title="t",
        severity=sev,
        resource=ResourceRef(kind="Deployment", name="api", namespace="prod"),
        message="m",
        risk_score=score,
    )


def test_scan_result_sorting_and_counts():
    result = ScanResult()
    result.add(_finding(Severity.LOW, score=20))
    result.add(_finding(Severity.CRITICAL, score=90))
    result.add(_finding(Severity.MEDIUM, score=45))

    ordered = result.sorted_findings()
    assert [f.severity for f in ordered] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    assert result.max_severity() == Severity.CRITICAL
    counts = result.counts_by_severity()
    assert counts["CRITICAL"] == 1
    assert counts["MEDIUM"] == 1
    assert counts["LOW"] == 1
    assert counts["HIGH"] == 0


def test_finding_to_dict_roundtrip_fields():
    f = _finding(Severity.HIGH)
    f.change = ChangeAction.DELETE
    data = f.to_dict()
    assert data["severity"] == "HIGH"
    assert data["change"] == "delete"
    assert data["resource"]["node_id"] == "k8s:Deployment/prod/api"


def test_empty_result_max_severity_none():
    assert ScanResult().max_severity() is None
