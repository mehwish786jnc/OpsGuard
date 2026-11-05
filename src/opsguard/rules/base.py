"""Deterministic rule framework.

Rules are the heart of OpsGuard. Each rule encodes a single, well-understood
production risk. Rules are **deterministic** — given the same input they always
produce the same findings. AI is never consulted to decide whether something is
a risk; it is only used later to *explain* findings.

Two rule families exist:

* :class:`KubernetesRule` — evaluates a single :class:`K8sResource`.
* :class:`TerraformRule` — evaluates a single :class:`TfResourceChange`.

Rules self-register via the :func:`register` decorator, so adding a new rule is
as simple as writing a class and decorating it. This keeps the barrier to
contribution low.
"""

from __future__ import annotations

import abc
from typing import Dict, List, Optional, Type

from opsguard.models import Finding, Severity
from opsguard.scanner.kubernetes import K8sResource
from opsguard.scanner.terraform import TfResourceChange


class Rule:
    """Base class for all rules."""

    #: Stable, unique identifier, e.g. ``"K8S-PRIV-001"``. Used in reports and
    #: for suppression. Must never change once published.
    id: str = ""
    #: Short human-readable name.
    title: str = ""
    #: Default severity if the rule does not override per-finding.
    severity: Severity = Severity.MEDIUM
    #: External references (docs, CVEs, best-practice links).
    references: List[str] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Enforce that concrete rules declare an id.
        if not getattr(cls, "_abstract", False) and not cls.__dict__.get("id", cls.id):
            # Allow abstract intermediate classes without ids.
            pass


class KubernetesRule(Rule, abc.ABC):
    """A rule that evaluates a single Kubernetes resource."""

    #: Kubernetes kinds this rule applies to. Empty tuple means "all kinds".
    applies_to: tuple = ()

    def matches(self, resource: K8sResource) -> bool:
        return not self.applies_to or resource.kind in self.applies_to

    @abc.abstractmethod
    def evaluate(self, resource: K8sResource) -> List[Finding]:
        """Return zero or more findings for ``resource``."""
        raise NotImplementedError


class TerraformRule(Rule, abc.ABC):
    """A rule that evaluates a single Terraform resource change."""

    #: Terraform resource types this rule applies to. Empty means "all".
    applies_to: tuple = ()

    def matches(self, change: TfResourceChange) -> bool:
        return not self.applies_to or change.type in self.applies_to

    @abc.abstractmethod
    def evaluate(self, change: TfResourceChange) -> List[Finding]:
        """Return zero or more findings for ``change``."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_K8S_RULES: Dict[str, KubernetesRule] = {}
_TF_RULES: Dict[str, TerraformRule] = {}


def register(cls: Type[Rule]) -> Type[Rule]:
    """Class decorator that instantiates and registers a rule."""
    if not getattr(cls, "id", ""):
        raise ValueError(f"Rule {cls.__name__} must define a non-empty 'id'.")
    instance = cls()  # type: ignore[call-arg]
    if isinstance(instance, KubernetesRule):
        if cls.id in _K8S_RULES:
            raise ValueError(f"Duplicate rule id: {cls.id}")
        _K8S_RULES[cls.id] = instance
    elif isinstance(instance, TerraformRule):
        if cls.id in _TF_RULES:
            raise ValueError(f"Duplicate rule id: {cls.id}")
        _TF_RULES[cls.id] = instance
    else:  # pragma: no cover - defensive
        raise TypeError(f"{cls.__name__} must subclass KubernetesRule or TerraformRule")
    return cls


def kubernetes_rules(disabled: Optional[set] = None) -> List[KubernetesRule]:
    disabled = disabled or set()
    return [r for rid, r in sorted(_K8S_RULES.items()) if rid not in disabled]


def terraform_rules(disabled: Optional[set] = None) -> List[TerraformRule]:
    disabled = disabled or set()
    return [r for rid, r in sorted(_TF_RULES.items()) if rid not in disabled]


def all_rule_ids() -> List[str]:
    return sorted(list(_K8S_RULES) + list(_TF_RULES))
