"""Shared pytest fixtures."""

from __future__ import annotations

import os

import pytest

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")


@pytest.fixture
def examples_dir() -> str:
    return EXAMPLES


@pytest.fixture
def risky_k8s_dir(examples_dir: str) -> str:
    return os.path.join(examples_dir, "risky-k8s")


@pytest.fixture
def safe_k8s_dir(examples_dir: str) -> str:
    return os.path.join(examples_dir, "safe-k8s")


@pytest.fixture
def tf_plan(examples_dir: str) -> str:
    return os.path.join(examples_dir, "terraform", "tfplan.json")


@pytest.fixture
def helm_chart_dir(examples_dir: str) -> str:
    return os.path.join(examples_dir, "helm-chart")


@pytest.fixture
def kustomize_dir(examples_dir: str) -> str:
    return os.path.join(examples_dir, "kustomize")
