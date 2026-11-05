"""Tests for Terraform rules."""

from __future__ import annotations

from typing import List

from opsguard.models import ChangeAction, Finding, Severity
from opsguard.rules import get_terraform_rules
from opsguard.scanner.terraform import TfResourceChange


def _change(**kwargs) -> TfResourceChange:
    defaults = {
        "address": "aws_x.y",
        "type": "aws_x",
        "name": "y",
        "actions": ["update"],
        "before": None,
        "after": {},
    }
    defaults.update(kwargs)
    return TfResourceChange(**defaults)


def _run(change: TfResourceChange) -> List[Finding]:
    findings: List[Finding] = []
    for rule in get_terraform_rules():
        if rule.matches(change):
            findings.extend(rule.evaluate(change))
    return findings


def _ids(findings: List[Finding]) -> set:
    return {f.rule_id for f in findings}


def test_change_action_replace():
    c = _change(actions=["delete", "create"])
    assert c.change_action == ChangeAction.REPLACE
    assert c.is_destroy


def test_change_action_delete():
    c = _change(actions=["delete"])
    assert c.change_action == ChangeAction.DELETE
    assert c.is_destroy


def test_stateful_destroy_is_critical():
    c = _change(type="aws_db_instance", name="db", actions=["delete"], before={"id": "x"}, after=None)
    findings = _run(c)
    assert "TF-DESTROY-001" in _ids(findings)
    assert findings[0].severity == Severity.CRITICAL


def test_stateful_create_not_flagged_as_destroy():
    c = _change(type="aws_db_instance", name="db", actions=["create"], after={"id": "x"})
    assert "TF-DESTROY-001" not in _ids(_run(c))


def test_security_group_open_to_world():
    c = _change(
        type="aws_security_group",
        name="db",
        actions=["update"],
        after={
            "ingress": [
                {"from_port": 5432, "to_port": 5432, "cidr_blocks": ["0.0.0.0/0"]}
            ]
        },
    )
    assert "TF-NET-001" in _ids(_run(c))


def test_security_group_restricted_not_flagged():
    c = _change(
        type="aws_security_group",
        name="db",
        actions=["update"],
        after={
            "ingress": [
                {"from_port": 5432, "to_port": 5432, "cidr_blocks": ["10.0.0.0/16"]}
            ]
        },
    )
    assert "TF-NET-001" not in _ids(_run(c))


def test_s3_public_read_write_is_critical():
    c = _change(
        type="aws_s3_bucket_acl",
        name="b",
        actions=["create"],
        after={"acl": "public-read-write"},
    )
    findings = [f for f in _run(c) if f.rule_id == "TF-S3-001"]
    assert findings and findings[0].severity == Severity.CRITICAL


def test_iam_wildcard_admin_is_critical():
    policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    c = _change(
        type="aws_iam_role_policy",
        name="admin",
        actions=["create"],
        after={"policy": policy},
    )
    findings = [f for f in _run(c) if f.rule_id == "TF-IAM-001"]
    assert findings and findings[0].severity == Severity.CRITICAL


def test_rds_public_and_unencrypted():
    c = _change(
        type="aws_db_instance",
        name="analytics",
        actions=["create"],
        after={"publicly_accessible": True, "storage_encrypted": False},
    )
    ids = _ids(_run(c))
    assert "TF-RDS-001" in ids
    assert "TF-RDS-002" in ids
