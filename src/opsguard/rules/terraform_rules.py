"""Terraform deterministic rules.

These rules reason about *changes* (create/update/delete/replace) rather than
static config, because the Terraform plan already tells us precisely what will
happen. The highest-severity findings concern destruction or replacement of
stateful resources and newly public exposure.
"""

from __future__ import annotations

from typing import Any, Dict, List

from opsguard.models import ChangeAction, Finding, Severity
from opsguard.rules.base import TerraformRule, register
from opsguard.scanner.terraform import TfResourceChange

# Resource types that typically hold irreplaceable state. Destroying or
# replacing these can cause permanent data loss.
STATEFUL_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_rds_cluster_instance",
    "aws_dynamodb_table",
    "aws_s3_bucket",
    "aws_elasticache_cluster",
    "aws_efs_file_system",
    "aws_ebs_volume",
    "aws_redshift_cluster",
    "google_sql_database_instance",
    "google_storage_bucket",
    "google_compute_disk",
    "azurerm_sql_database",
    "azurerm_storage_account",
    "azurerm_managed_disk",
    "azurerm_postgresql_server",
    "azurerm_mysql_server",
}

SENSITIVE_PORTS = {
    22: "SSH",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    3389: "RDP",
    9200: "Elasticsearch",
    5984: "CouchDB",
    11211: "Memcached",
    1433: "MSSQL",
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


@register
class DestructiveStatefulChange(TerraformRule):
    id = "TF-DESTROY-001"
    title = "Destruction or replacement of a stateful resource"
    severity = Severity.CRITICAL

    def matches(self, change: TfResourceChange) -> bool:
        return change.type in STATEFUL_TYPES

    def evaluate(self, change: TfResourceChange) -> List[Finding]:
        if not change.is_destroy:
            return []
        verb = "replaced (destroyed and recreated)" if change.change_action == ChangeAction.REPLACE else "destroyed"
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                resource=change.ref,
                change=change.change_action,
                message=f"{change.address} will be {verb}.",
                impact=(
                    "This resource stores persistent data. Destroying or replacing it can cause "
                    "permanent, unrecoverable data loss and downtime."
                ),
                remediation=(
                    "Confirm this is intentional. Take a verified backup/snapshot first. Consider "
                    "'prevent_destroy = true' in a lifecycle block, or use 'create_before_destroy' "
                    "with a migration plan. Investigate why a replace is triggered (often an "
                    "immutable attribute changed)."
                ),
                evidence={"actions": change.actions},
            )
        ]


@register
class SecurityGroupOpenToWorld(TerraformRule):
    id = "TF-NET-001"
    title = "Security group opens a sensitive port to the internet"
    severity = Severity.HIGH
    applies_to = ("aws_security_group", "aws_security_group_rule")

    def evaluate(self, change: TfResourceChange) -> List[Finding]:
        if change.change_action in (ChangeAction.DELETE, ChangeAction.NOOP):
            return []
        cfg = change.config()
        findings: List[Finding] = []

        ingress_blocks: List[Dict[str, Any]] = []
        if change.type == "aws_security_group":
            ingress_blocks = [b for b in _as_list(cfg.get("ingress")) if isinstance(b, dict)]
        elif change.type == "aws_security_group_rule" and cfg.get("type") == "ingress":
            ingress_blocks = [cfg]

        for block in ingress_blocks:
            cidrs = set(_as_list(block.get("cidr_blocks"))) | set(_as_list(block.get("ipv6_cidr_blocks")))
            if not (cidrs & OPEN_CIDRS):
                continue
            from_port = block.get("from_port")
            to_port = block.get("to_port")
            flagged = self._sensitive_in_range(from_port, to_port)
            if flagged:
                ports = ", ".join(f"{p} ({name})" for p, name in flagged)
                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        resource=change.ref,
                        change=change.change_action,
                        message=(
                            f"{change.address} allows 0.0.0.0/0 ingress to sensitive port(s): {ports}."
                        ),
                        impact="Exposing admin/database ports to the whole internet invites brute-force and exploitation.",
                        remediation="Restrict 'cidr_blocks' to known office/VPC ranges, or front the service with a bastion/VPN.",
                        evidence={"from_port": from_port, "to_port": to_port, "cidr_blocks": sorted(cidrs)},
                    )
                )
        return findings

    def _sensitive_in_range(self, from_port: Any, to_port: Any) -> List[tuple]:
        try:
            lo = int(from_port)
            hi = int(to_port)
        except (TypeError, ValueError):
            return []
        if lo == 0 and hi == 0:
            return []
        # A wide-open range (e.g. 0-65535) is itself dangerous.
        flagged = [(p, name) for p, name in SENSITIVE_PORTS.items() if lo <= p <= hi]
        return flagged


@register
class S3BucketPublic(TerraformRule):
    id = "TF-S3-001"
    title = "S3 bucket is publicly accessible"
    severity = Severity.HIGH
    applies_to = ("aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_public_access_block")

    def evaluate(self, change: TfResourceChange) -> List[Finding]:
        if change.change_action in (ChangeAction.DELETE, ChangeAction.NOOP):
            return []
        cfg = change.config()

        if change.type == "aws_s3_bucket_public_access_block":
            disabled = [
                k
                for k in (
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                )
                if cfg.get(k) is False
            ]
            if disabled:
                return [
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        resource=change.ref,
                        change=change.change_action,
                        message=f"{change.address} disables public-access protections: {', '.join(disabled)}.",
                        impact="Objects in the bucket may become publicly readable or writable, risking data leaks.",
                        remediation="Set all four public-access-block flags to true unless public hosting is intended and reviewed.",
                        evidence={"disabled": disabled},
                    )
                ]
            return []

        acl = cfg.get("acl")
        if acl in ("public-read", "public-read-write"):
            return [
                Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=Severity.CRITICAL if acl == "public-read-write" else self.severity,
                    resource=change.ref,
                    change=change.change_action,
                    message=f"{change.address} sets ACL '{acl}'.",
                    impact="A public ACL exposes bucket contents to anyone on the internet.",
                    remediation="Use 'private' ACL and grant access via IAM/bucket policy. Enable an aws_s3_bucket_public_access_block.",
                    evidence={"acl": acl},
                )
            ]
        return []


@register
class RdsPublic(TerraformRule):
    id = "TF-RDS-001"
    title = "Database is publicly accessible or unencrypted"
    severity = Severity.HIGH
    applies_to = ("aws_db_instance", "aws_rds_cluster")

    def evaluate(self, change: TfResourceChange) -> List[Finding]:
        if change.change_action in (ChangeAction.DELETE, ChangeAction.NOOP):
            return []
        cfg = change.config()
        findings = []
        if cfg.get("publicly_accessible") is True:
            findings.append(
                Finding(
                    rule_id=self.id,
                    title="Database is publicly accessible",
                    severity=Severity.HIGH,
                    resource=change.ref,
                    change=change.change_action,
                    message=f"{change.address} sets publicly_accessible = true.",
                    impact="The database receives a public endpoint, exposing it to internet-based attacks.",
                    remediation="Set 'publicly_accessible = false' and place the database in private subnets.",
                )
            )
        if cfg.get("storage_encrypted") is False:
            findings.append(
                Finding(
                    rule_id="TF-RDS-002",
                    title="Database storage is not encrypted",
                    severity=Severity.MEDIUM,
                    resource=change.ref,
                    change=change.change_action,
                    message=f"{change.address} sets storage_encrypted = false.",
                    impact="Data at rest is unencrypted, failing most compliance baselines.",
                    remediation="Set 'storage_encrypted = true' (note: enabling it may require a replacement).",
                )
            )
        return findings


@register
class IamWildcard(TerraformRule):
    id = "TF-IAM-001"
    title = "IAM policy grants wildcard permissions"
    severity = Severity.HIGH
    applies_to = (
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    )

    def evaluate(self, change: TfResourceChange) -> List[Finding]:
        if change.change_action in (ChangeAction.DELETE, ChangeAction.NOOP):
            return []
        cfg = change.config()
        policy = cfg.get("policy")
        if not isinstance(policy, str):
            return []
        statements = self._extract_statements(policy)
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = {str(a) for a in _as_list(stmt.get("Action"))}
            resources = {str(r) for r in _as_list(stmt.get("Resource"))}
            if "*" in actions and "*" in resources:
                return [
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        resource=change.ref,
                        change=change.change_action,
                        message=f"{change.address} allows Action '*' on Resource '*'.",
                        impact="This grants full administrative access; a leaked credential would compromise the entire account.",
                        remediation="Scope actions and resources to the minimum required (least privilege).",
                        evidence={"effect": "Allow", "action": "*", "resource": "*"},
                    )
                ]
            if "*" in actions:
                return [
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        resource=change.ref,
                        change=change.change_action,
                        message=f"{change.address} allows wildcard Action '*'.",
                        impact="Wildcard actions grant far more permission than typically needed.",
                        remediation="Replace '*' with the specific actions the principal requires.",
                        evidence={"effect": "Allow", "action": "*"},
                    )
                ]
        return []

    @staticmethod
    def _extract_statements(policy: str) -> List[Dict[str, Any]]:
        import json

        try:
            doc = json.loads(policy)
        except (json.JSONDecodeError, TypeError):
            return []
        stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
        return [s for s in _as_list(stmts) if isinstance(s, dict)]
