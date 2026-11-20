"""Render templated Kubernetes sources to plain manifest YAML.

Most teams don't commit raw manifests — they commit **Helm charts**
(``Chart.yaml`` + Go-templated ``templates/``) or **Kustomize overlays**
(``kustomization.yaml``). This module turns those into the plain multi-document
YAML that the rest of OpsGuard already understands.

Rendering a Helm chart means executing Go templates, which has no viable
pure-Python path, so we shell out to the standard tools (``helm``, and
``kustomize`` or ``kubectl``) — exactly what CI and humans run. The tools are
optional: if a required binary is missing or a render fails, we return a clear
error string and the caller records it and skips that source. A missing tool
never aborts a scan of sibling raw YAML.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Optional, Tuple

_HELM_CHART_FILE = "Chart.yaml"
_KUSTOMIZE_FILES = ("kustomization.yaml", "kustomization.yml", "Kustomization")

# Generous ceiling: real charts/overlays render in well under a second, but a
# pathological template or a hung hook plugin should not wedge a scan forever.
_RENDER_TIMEOUT = 60  # seconds


def is_helm_chart(path: str) -> bool:
    """True if ``path`` is a directory that looks like a Helm chart root."""
    return os.path.isdir(path) and os.path.isfile(os.path.join(path, _HELM_CHART_FILE))


def is_kustomize_dir(path: str) -> bool:
    """True if ``path`` is a directory holding a kustomization file."""
    return os.path.isdir(path) and any(
        os.path.isfile(os.path.join(path, name)) for name in _KUSTOMIZE_FILES
    )


def is_render_root(path: str) -> bool:
    """True if ``path`` is a Helm chart or a Kustomize overlay directory."""
    return is_helm_chart(path) or is_kustomize_dir(path)


def _run(cmd: List[str], *, tool: str, label: str) -> Tuple[str, Optional[str]]:
    """Run ``cmd`` (``cmd[0]`` is the binary) and capture stdout.

    Returns ``(stdout, None)`` on success, or ``("", error)`` when the binary is
    missing, the command exits non-zero, or it times out.
    """
    if shutil.which(cmd[0]) is None:
        return "", f"{label}: '{cmd[0]}' not found on PATH — install it to scan this source"
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell, trusted binary
            cmd,
            capture_output=True,
            text=True,
            timeout=_RENDER_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "", f"{label}: {tool} timed out after {_RENDER_TIMEOUT}s"
    except OSError as exc:
        return "", f"{label}: {tool} failed to execute: {exc}"
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else f"exit code {proc.returncode}"
        return "", f"{label}: {tool} failed: {reason}"
    return proc.stdout, None


def render_helm(
    chart_dir: str,
    values: Optional[List[str]] = None,
    release: str = "opsguard",
) -> Tuple[str, Optional[str]]:
    """Render a Helm chart to multi-document YAML via ``helm template``."""
    cmd = ["helm", "template", release, chart_dir]
    for path in values or []:
        cmd += ["--values", path]
    return _run(cmd, tool="helm", label=f"{chart_dir} (helm)")


def render_kustomize(path: str) -> Tuple[str, Optional[str]]:
    """Render a Kustomize overlay to multi-document YAML.

    Prefers standalone ``kustomize build``; falls back to ``kubectl kustomize``.
    """
    label = f"{path} (kustomize)"
    if shutil.which("kustomize") is not None:
        return _run(["kustomize", "build", path], tool="kustomize", label=label)
    if shutil.which("kubectl") is not None:
        return _run(["kubectl", "kustomize", path], tool="kubectl", label=label)
    return (
        "",
        f"{label}: neither 'kustomize' nor 'kubectl' found on PATH — "
        "install one to scan this overlay",
    )
