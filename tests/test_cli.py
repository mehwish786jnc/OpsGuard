"""CLI tests using Typer's test runner."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from opsguard.cli import app

runner = CliRunner(mix_stderr=False)


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "OpsGuard" in result.stdout


def test_rules_listing():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "K8S-SEC-001" in result.stdout
    assert "TF-DESTROY-001" in result.stdout


def test_scan_json_and_gate_fail(risky_k8s_dir):
    result = runner.invoke(app, ["scan", risky_k8s_dir, "--format", "json", "--fail-on", "high"])
    # Risky fixture has CRITICAL findings -> gate fails with exit code 1.
    assert result.exit_code == 1
    doc = json.loads(result.stdout)
    assert doc["summary"]["counts_by_severity"]["CRITICAL"] >= 1


def test_scan_safe_passes(safe_k8s_dir):
    result = runner.invoke(app, ["scan", safe_k8s_dir, "--fail-on", "high"])
    assert result.exit_code == 0


def test_scan_never_gate(risky_k8s_dir):
    result = runner.invoke(app, ["scan", risky_k8s_dir, "--fail-on", "never"])
    assert result.exit_code == 0


def test_scan_unknown_format(safe_k8s_dir):
    result = runner.invoke(app, ["scan", safe_k8s_dir, "--format", "xml"])
    assert result.exit_code == 2


def test_scan_requires_target():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2


def test_scan_disable_rule(risky_k8s_dir):
    result = runner.invoke(
        app,
        [
            "scan",
            risky_k8s_dir,
            "--format",
            "json",
            "--fail-on",
            "never",
            "--disable",
            "K8S-SEC-001",
        ],
    )
    assert result.exit_code == 0
    doc = json.loads(result.stdout)
    assert all(f["rule_id"] != "K8S-SEC-001" for f in doc["findings"])


def test_scan_no_render_skips_chart(helm_chart_dir):
    # A chart with no `helm` binary and --no-render must not warn or error.
    result = runner.invoke(app, ["scan", helm_chart_dir, "--no-render", "--fail-on", "never"])
    assert result.exit_code == 0
    assert "helm" not in result.stderr
