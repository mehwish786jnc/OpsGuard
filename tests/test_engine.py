"""End-to-end engine, scoring and report tests."""

from __future__ import annotations

import json

from opsguard.engine import ScanConfig, analyze
from opsguard.models import Severity
from opsguard.report import render_json, render_markdown, render_sarif, render_terminal


def test_analyze_risky_fixtures(risky_k8s_dir, tf_plan):
    result = analyze(ScanConfig(paths=[risky_k8s_dir], tf_plans=[tf_plan]))
    assert result.max_severity() == Severity.CRITICAL
    counts = result.counts_by_severity()
    assert counts["CRITICAL"] >= 3
    assert counts["HIGH"] >= 5
    # Every finding should have a non-zero risk score after scoring.
    assert all(f.risk_score > 0 for f in result.findings)


def test_analyze_safe_fixture_has_no_high(safe_k8s_dir):
    result = analyze(ScanConfig(paths=[safe_k8s_dir]))
    assert all(f.severity < Severity.HIGH for f in result.findings)


def test_min_severity_filter(risky_k8s_dir):
    result = analyze(ScanConfig(paths=[risky_k8s_dir], min_severity=Severity.HIGH))
    assert all(f.severity >= Severity.HIGH for f in result.findings)


def test_disable_rule(risky_k8s_dir):
    result = analyze(ScanConfig(paths=[risky_k8s_dir], disabled_rules={"K8S-SEC-001"}))
    assert all(f.rule_id != "K8S-SEC-001" for f in result.findings)


def test_scoring_blast_radius_bumps_score(risky_k8s_dir):
    result = analyze(ScanConfig(paths=[risky_k8s_dir]))
    priv = [f for f in result.findings if f.rule_id == "K8S-SEC-001"][0]
    # CRITICAL base is 90; blast radius should push it above 90.
    assert priv.risk_score >= 90


def test_json_report_is_valid(risky_k8s_dir, tf_plan):
    result = analyze(ScanConfig(paths=[risky_k8s_dir], tf_plans=[tf_plan]))
    doc = json.loads(render_json(result))
    assert doc["summary"]["total_findings"] == len(result.findings)
    assert "findings" in doc


def test_sarif_report_is_valid(risky_k8s_dir):
    result = analyze(ScanConfig(paths=[risky_k8s_dir]))
    doc = json.loads(render_sarif(result))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "OpsGuard"
    assert len(doc["runs"][0]["results"]) == len(result.findings)


def test_markdown_report_contains_table(risky_k8s_dir):
    result = analyze(ScanConfig(paths=[risky_k8s_dir]))
    md = render_markdown(result)
    assert "OpsGuard" in md
    assert "| Severity |" in md


def test_markdown_clean_report(safe_k8s_dir):
    result = analyze(ScanConfig(paths=[safe_k8s_dir]))
    md = render_markdown(result)
    assert "No risks detected" in md


def test_terminal_report_renders(risky_k8s_dir):
    result = analyze(ScanConfig(paths=[risky_k8s_dir]))
    out = render_terminal(result, use_color=False)
    assert "OpsGuard" in out


def test_ai_offline_explanations(risky_k8s_dir):
    result = analyze(
        ScanConfig(paths=[risky_k8s_dir], with_ai=True, ai_provider="offline")
    )
    assert all(f.ai_explanation for f in result.findings)
