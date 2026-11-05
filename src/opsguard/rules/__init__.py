"""Rule registry package.

Importing this package registers all built-in rules as a side effect, so the
engine can simply do ``import opsguard.rules`` and then query the registry.
"""

from opsguard.rules import kubernetes_rules, terraform_rules  # noqa: F401
from opsguard.rules.base import (
    all_rule_ids,
    register,
)
from opsguard.rules.base import (
    kubernetes_rules as get_kubernetes_rules,
)
from opsguard.rules.base import (
    terraform_rules as get_terraform_rules,
)

__all__ = [
    "all_rule_ids",
    "get_kubernetes_rules",
    "get_terraform_rules",
    "register",
]
