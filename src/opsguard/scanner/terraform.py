"""Terraform plan scanner.

Consumes the JSON representation of a Terraform plan produced with::

    terraform plan -out tfplan.binary
    terraform show -json tfplan.binary > tfplan.json

The plan's ``resource_changes`` array is the authoritative source of *what is
changing*, which is exactly what OpsGuard cares about. We normalize each entry
into a :class:`TfResourceChange`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from opsguard.models import ChangeAction, ResourceRef


@dataclass
class TfResourceChange:
    """A single resource change extracted from a Terraform plan."""

    address: str
    type: str
    name: str
    actions: List[str]
    before: Optional[Dict[str, Any]]
    after: Optional[Dict[str, Any]]
    after_unknown: Dict[str, Any] = field(default_factory=dict)
    file: str = ""
    provider_name: str = ""

    @property
    def ref(self) -> ResourceRef:
        return ResourceRef(
            kind=self.type,
            name=self.name,
            provider="terraform",
            file=self.file or None,
        )

    @property
    def change_action(self) -> ChangeAction:
        acts = set(self.actions)
        if {"delete", "create"}.issubset(acts):
            return ChangeAction.REPLACE
        if "delete" in acts:
            return ChangeAction.DELETE
        if "create" in acts:
            return ChangeAction.CREATE
        if "update" in acts:
            return ChangeAction.UPDATE
        return ChangeAction.NOOP

    @property
    def is_destroy(self) -> bool:
        return self.change_action in (ChangeAction.DELETE, ChangeAction.REPLACE)

    def config(self) -> Dict[str, Any]:
        """The resulting configuration after the change (``after``), or ``before``
        for pure deletions."""
        if self.after:
            return self.after
        return self.before or {}


def scan_terraform_plan(file_path: str) -> Tuple[List[TfResourceChange], List[str]]:
    """Parse a Terraform plan JSON file.

    Returns ``(changes, errors)``.
    """
    errors: List[str] = []
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            plan = json.load(handle)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return [], [f"{file_path}: {exc}"]

    if not isinstance(plan, dict):
        return [], [f"{file_path}: expected a JSON object at the top level"]

    raw_changes = plan.get("resource_changes")
    if not isinstance(raw_changes, list):
        return [], [
            f"{file_path}: no 'resource_changes' array found. "
            "Generate it with `terraform show -json tfplan.binary`."
        ]

    changes: List[TfResourceChange] = []
    for entry in raw_changes:
        if not isinstance(entry, dict):
            continue
        change = entry.get("change", {})
        if not isinstance(change, dict):
            change = {}
        actions = change.get("actions", []) or []
        # Skip genuine no-ops; they carry no risk signal.
        if actions == ["no-op"] or not actions:
            continue
        changes.append(
            TfResourceChange(
                address=str(entry.get("address", "")),
                type=str(entry.get("type", "")),
                name=str(entry.get("name", "")),
                actions=[str(a) for a in actions],
                before=change.get("before") if isinstance(change.get("before"), dict) else None,
                after=change.get("after") if isinstance(change.get("after"), dict) else None,
                after_unknown=change.get("after_unknown", {}) or {},
                file=file_path,
                provider_name=str(entry.get("provider_name", "")),
            )
        )

    return changes, errors
