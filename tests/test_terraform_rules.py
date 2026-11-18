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
    c = _change(
        type="aws_db_instance", name="db", actions=["delete"], before={"id": "x"}, after=None
    )
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
        after={"ingress": [{"from_port": 5432, "to_port": 5432, "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    assert "TF-NET-001" in _ids(_run(c))


def test_security_group_restricted_not_flagged():
    c = _change(
        type="aws_security_group",
        name="db",
        actions=["update"],
        after={"ingress": [{"from_port": 5432, "to_port": 5432, "cidr_blocks": ["10.0.0.0/16"]}]},
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


# --------------------------------------------------------------------------- #
# Edge cases: deletions, no-ops, and malformed input must stay quiet/safe.
# --------------------------------------------------------------------------- #


def test_delete_of_security_group_not_flagged():
    c = _change(
        type="aws_security_group",
        name="db",
        actions=["delete"],
        before={"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]},
        after=None,
    )
    assert "TF-NET-001" not in _ids(_run(c))


def test_security_group_rule_ingress_ipv6_open():
    c = _change(
        type="aws_security_group_rule",
        name="r",
        actions=["create"],
        after={
            "type": "ingress",
            "from_port": 22,
            "to_port": 22,
            "ipv6_cidr_blocks": ["::/0"],
        },
    )
    assert "TF-NET-001" in _ids(_run(c))


def test_security_group_non_sensitive_port_not_flagged():
    c = _change(
        type="aws_security_group",
        name="web",
        actions=["create"],
        after={"ingress": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    assert "TF-NET-001" not in _ids(_run(c))


def test_security_group_zero_zero_port_range_ignored():
    # from_port == to_port == 0 is the "all protocols" placeholder, not a port.
    c = _change(
        type="aws_security_group",
        name="all",
        actions=["create"],
        after={"ingress": [{"from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    assert "TF-NET-001" not in _ids(_run(c))


def test_s3_public_access_block_disabled_flagged():
    c = _change(
        type="aws_s3_bucket_public_access_block",
        name="b",
        actions=["update"],
        after={"block_public_acls": False, "block_public_policy": True},
    )
    findings = [f for f in _run(c) if f.rule_id == "TF-S3-001"]
    assert findings
    assert "block_public_acls" in findings[0].evidence["disabled"]


def test_s3_public_access_block_all_true_quiet():
    c = _change(
        type="aws_s3_bucket_public_access_block",
        name="b",
        actions=["create"],
        after={
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        },
    )
    assert "TF-S3-001" not in _ids(_run(c))


def test_s3_private_acl_not_flagged():
    c = _change(type="aws_s3_bucket_acl", name="b", actions=["create"], after={"acl": "private"})
    assert "TF-S3-001" not in _ids(_run(c))


def test_s3_public_read_is_high_not_critical():
    c = _change(
        type="aws_s3_bucket_acl", name="b", actions=["create"], after={"acl": "public-read"}
    )
    findings = [f for f in _run(c) if f.rule_id == "TF-S3-001"]
    assert findings and findings[0].severity == Severity.HIGH


def test_iam_wildcard_action_only_is_high():
    policy = '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/*"}]}'
    c = _change(type="aws_iam_policy", name="p", actions=["create"], after={"policy": policy})
    findings = [f for f in _run(c) if f.rule_id == "TF-IAM-001"]
    assert findings and findings[0].severity == Severity.HIGH


def test_iam_malformed_policy_quiet():
    c = _change(type="aws_iam_policy", name="p", actions=["create"], after={"policy": "not-json"})
    assert "TF-IAM-001" not in _ids(_run(c))


def test_iam_non_string_policy_quiet():
    c = _change(type="aws_iam_policy", name="p", actions=["create"], after={"policy": {"a": 1}})
    assert "TF-IAM-001" not in _ids(_run(c))


def test_iam_deny_wildcard_not_flagged():
    policy = '{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
    c = _change(type="aws_iam_policy", name="p", actions=["create"], after={"policy": policy})
    assert "TF-IAM-001" not in _ids(_run(c))


def test_rds_encrypted_private_quiet():
    c = _change(
        type="aws_db_instance",
        name="db",
        actions=["create"],
        after={"publicly_accessible": False, "storage_encrypted": True},
    )
    assert not _ids(_run(c))
