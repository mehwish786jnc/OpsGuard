"""Tests for Helm/Kustomize rendering and the render-aware Kubernetes scanner.

Rendering shells out to ``helm``/``kustomize``/``kubectl``. To stay offline and
deterministic (and to not require those binaries in CI), the unit tests
monkeypatch ``shutil.which`` and ``subprocess.run``. One opt-in test exercises a
real ``kustomize``/``kubectl`` render when a binary is present.
"""

from __future__ import annotations

import shutil
import subprocess
import types

import pytest

from opsguard.engine import ScanConfig, analyze
from opsguard.scanner import kubernetes as k8s
from opsguard.scanner import render
from opsguard.scanner.kubernetes import scan_kubernetes

CANNED_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: production
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: mycorp/web:latest
          securityContext:
            privileged: true
"""


def _fake_proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# --- detection -------------------------------------------------------------


def test_detection_helpers(helm_chart_dir, kustomize_dir, safe_k8s_dir):
    assert render.is_helm_chart(helm_chart_dir)
    assert not render.is_kustomize_dir(helm_chart_dir)
    assert render.is_kustomize_dir(kustomize_dir)
    assert not render.is_helm_chart(kustomize_dir)
    assert render.is_render_root(helm_chart_dir)
    assert render.is_render_root(kustomize_dir)
    # A directory of raw manifests is not a render root.
    assert not render.is_render_root(safe_k8s_dir)


# --- render_helm -----------------------------------------------------------


def test_render_helm_success(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _fake_proc(stdout=CANNED_MANIFEST)

    monkeypatch.setattr(render.shutil, "which", lambda _b: "/usr/bin/helm")
    monkeypatch.setattr(render.subprocess, "run", fake_run)

    out, err = render.render_helm("mychart", values=["prod.yaml"])
    assert err is None
    assert "kind: Deployment" in out
    assert captured["cmd"][:4] == ["helm", "template", "opsguard", "mychart"]
    assert "--values" in captured["cmd"] and "prod.yaml" in captured["cmd"]


def test_render_helm_missing_binary(monkeypatch):
    monkeypatch.setattr(render.shutil, "which", lambda _b: None)
    out, err = render.render_helm("mychart")
    assert out == ""
    assert "not found" in err and "helm" in err


def test_render_helm_nonzero_exit(monkeypatch):
    monkeypatch.setattr(render.shutil, "which", lambda _b: "/usr/bin/helm")
    monkeypatch.setattr(
        render.subprocess,
        "run",
        lambda *a, **k: _fake_proc(returncode=1, stderr="Error: values file not found"),
    )
    out, err = render.render_helm("mychart")
    assert out == ""
    assert "values file not found" in err


def test_render_helm_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="helm", timeout=60)

    monkeypatch.setattr(render.shutil, "which", lambda _b: "/usr/bin/helm")
    monkeypatch.setattr(render.subprocess, "run", boom)
    out, err = render.render_helm("mychart")
    assert out == ""
    assert "timed out" in err


# --- render_kustomize ------------------------------------------------------


def test_render_kustomize_prefers_kustomize(monkeypatch):
    captured = {}
    monkeypatch.setattr(render.shutil, "which", lambda b: "/usr/bin/" + b)

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _fake_proc(stdout=CANNED_MANIFEST)

    monkeypatch.setattr(render.subprocess, "run", fake_run)
    out, err = render.render_kustomize("overlay")
    assert err is None
    assert captured["cmd"] == ["kustomize", "build", "overlay"]


def test_render_kustomize_falls_back_to_kubectl(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        render.shutil, "which", lambda b: None if b == "kustomize" else "/bin/kubectl"
    )

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _fake_proc(stdout="")

    monkeypatch.setattr(render.subprocess, "run", fake_run)
    render.render_kustomize("overlay")
    assert captured["cmd"] == ["kubectl", "kustomize", "overlay"]


def test_render_kustomize_no_tool(monkeypatch):
    monkeypatch.setattr(render.shutil, "which", lambda _b: None)
    out, err = render.render_kustomize("overlay")
    assert out == ""
    assert "neither" in err


# --- scanner integration (render seam mocked) ------------------------------


def test_scan_renders_helm_chart(monkeypatch, helm_chart_dir):
    monkeypatch.setattr(k8s, "render_helm", lambda path, values: (CANNED_MANIFEST, None))
    resources, files, errors = scan_kubernetes(helm_chart_dir)
    assert errors == []
    assert [r.kind for r in resources] == ["Deployment"]
    assert resources[0].name == "web"
    assert any("(helm)" in f for f in files)


def test_scan_helm_error_is_recorded(monkeypatch, helm_chart_dir):
    monkeypatch.setattr(k8s, "render_helm", lambda path, values: ("", "boom: helm exploded"))
    resources, files, errors = scan_kubernetes(helm_chart_dir)
    assert resources == []
    assert errors == ["boom: helm exploded"]


def test_no_render_skips_chart(helm_chart_dir):
    resources, files, errors = scan_kubernetes(helm_chart_dir, render=False)
    assert resources == []
    assert files == []
    assert errors == []  # template files are skipped, not mis-parsed


def test_nested_chart_is_pruned_from_raw_walk(monkeypatch, tmp_path):
    # A raw manifest alongside a chart subdirectory whose template is invalid YAML.
    (tmp_path / "svc.yaml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: raw\nspec: {}\n"
    )
    chart = tmp_path / "subchart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: subchart\nversion: 0.1.0\n")
    # Go-template content that would raise a YAML error if parsed as raw YAML.
    (chart / "templates" / "deploy.yaml").write_text("foo: {{ .Values.bar }\n")

    monkeypatch.setattr(k8s, "render_helm", lambda path, values: (CANNED_MANIFEST, None))
    resources, files, errors = scan_kubernetes(str(tmp_path))

    kinds = sorted(r.kind for r in resources)
    assert kinds == ["Deployment", "Service"]  # rendered chart + raw svc
    assert errors == []  # the chart's template was never parsed as raw YAML


def test_engine_render_flag_threads_through(monkeypatch, helm_chart_dir):
    monkeypatch.setattr(k8s, "render_helm", lambda path, values: (CANNED_MANIFEST, None))
    result = analyze(ScanConfig(paths=[helm_chart_dir]))
    # Rendered manifest is privileged + latest + single-replica → findings exist.
    assert any(f.rule_id == "K8S-SEC-001" for f in result.findings)

    result_off = analyze(ScanConfig(paths=[helm_chart_dir], render=False))
    assert result_off.findings == []


# --- opt-in real render ----------------------------------------------------


@pytest.mark.skipif(
    shutil.which("kustomize") is None and shutil.which("kubectl") is None,
    reason="requires kustomize or kubectl on PATH",
)
def test_real_kustomize_render(kustomize_dir):
    resources, files, errors = scan_kubernetes(kustomize_dir)
    assert errors == []
    deploys = [r for r in resources if r.kind == "Deployment"]
    assert deploys, "expected a Deployment from the rendered overlay"
    # The kustomize images transformer rewrites the tag to :latest.
    assert deploys[0].containers()[0]["image"].endswith(":latest")
