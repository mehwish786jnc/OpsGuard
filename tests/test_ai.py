"""Tests for the AI explanation layer.

AI never decides risk — it only explains findings — and every provider failure
must degrade gracefully to the deterministic offline explanation. These tests
exercise every provider path with ``requests`` fully stubbed (no network).
"""

from __future__ import annotations

import sys
import types

import pytest

from opsguard import ai
from opsguard.models import Finding, ResourceRef, Severity


def _finding(**kwargs) -> Finding:
    defaults = {
        "rule_id": "K8S-SEC-001",
        "title": "Privileged container",
        "severity": Severity.CRITICAL,
        "resource": ResourceRef(kind="Deployment", name="api", namespace="prod"),
        "message": "Container runs privileged.",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


# --------------------------------------------------------------------------- #
# offline_explanation
# --------------------------------------------------------------------------- #


def test_offline_explanation_minimal():
    text = ai.offline_explanation(_finding())
    assert "Container runs privileged." in text
    assert "Why it matters" not in text  # no impact supplied


def test_offline_explanation_full():
    f = _finding(
        impact="Full node access.",
        remediation="Drop privileged: true.",
        affected=["Service/api", "Ingress/api"],
    )
    text = ai.offline_explanation(f)
    assert "Why it matters: Full node access." in text
    assert "How to fix: Drop privileged: true." in text
    assert "Blast radius" in text and "Service/api" in text


def test_offline_explanation_truncates_blast_radius():
    f = _finding(affected=[f"svc-{i}" for i in range(8)])
    text = ai.offline_explanation(f)
    assert "(+3 more)" in text  # 8 affected, 5 shown


# --------------------------------------------------------------------------- #
# explain_findings — provider dispatch & fallback
# --------------------------------------------------------------------------- #


def test_explain_findings_offline_default():
    findings = [_finding()]
    ai.explain_findings(findings)  # default provider == offline
    assert findings[0].ai_explanation
    assert findings[0].ai_explanation == ai.offline_explanation(_finding())


def test_explain_findings_unknown_provider_falls_back():
    findings = [_finding()]
    ai.explain_findings(findings, provider="does-not-exist")
    assert findings[0].ai_explanation == ai.offline_explanation(_finding())


def test_explain_findings_none_provider_falls_back():
    findings = [_finding()]
    ai.explain_findings(findings, provider=None)  # type: ignore[arg-type]
    assert findings[0].ai_explanation


# --------------------------------------------------------------------------- #
# requests stubbing helpers
# --------------------------------------------------------------------------- #


class _FakeResponse:
    def __init__(self, payload, status_ok=True):
        self._payload = payload
        self._ok = status_ok

    def raise_for_status(self):
        if not self._ok:
            raise RuntimeError("HTTP 500")

    def json(self):
        return self._payload


def _install_fake_requests(monkeypatch, post):
    module = types.ModuleType("requests")
    module.post = post  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "requests", module)


# --------------------------------------------------------------------------- #
# Ollama
# --------------------------------------------------------------------------- #


def test_ollama_success(monkeypatch):
    def fake_post(url, json=None, timeout=None, **kw):
        assert "/api/generate" in url
        return _FakeResponse({"response": "Ollama says: drop the flag."})

    _install_fake_requests(monkeypatch, fake_post)
    findings = [_finding()]
    ai.explain_findings(findings, provider="ollama", model="llama3")
    assert findings[0].ai_explanation == "Ollama says: drop the flag."


def test_ollama_http_error_falls_back(monkeypatch):
    def fake_post(url, json=None, timeout=None, **kw):
        return _FakeResponse({}, status_ok=False)

    _install_fake_requests(monkeypatch, fake_post)
    findings = [_finding()]
    ai.explain_findings(findings, provider="ollama")
    assert findings[0].ai_explanation == ai.offline_explanation(_finding())


def test_ollama_empty_response_falls_back(monkeypatch):
    def fake_post(url, json=None, timeout=None, **kw):
        return _FakeResponse({"response": "   "})

    _install_fake_requests(monkeypatch, fake_post)
    findings = [_finding()]
    ai.explain_findings(findings, provider="ollama")
    assert findings[0].ai_explanation == ai.offline_explanation(_finding())


def test_ollama_missing_requests_falls_back(monkeypatch):
    # Simulate the optional 'requests' dependency being absent.
    monkeypatch.setitem(sys.modules, "requests", None)
    findings = [_finding()]
    ai.explain_findings(findings, provider="ollama")
    assert findings[0].ai_explanation == ai.offline_explanation(_finding())


# --------------------------------------------------------------------------- #
# Gemini
# --------------------------------------------------------------------------- #


def test_gemini_success(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def fake_post(url, json=None, timeout=None, **kw):
        assert "generativelanguage.googleapis.com" in url
        return _FakeResponse(
            {"candidates": [{"content": {"parts": [{"text": "Gemini explanation."}]}}]}
        )

    _install_fake_requests(monkeypatch, fake_post)
    findings = [_finding()]
    ai.explain_findings(findings, provider="gemini")
    assert findings[0].ai_explanation == "Gemini explanation."


def test_gemini_without_api_key_falls_back(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    def fake_post(url, json=None, timeout=None, **kw):  # pragma: no cover - must not run
        raise AssertionError("should not call the API without a key")

    _install_fake_requests(monkeypatch, fake_post)
    findings = [_finding()]
    ai.explain_findings(findings, provider="gemini")
    assert findings[0].ai_explanation == ai.offline_explanation(_finding())


def test_gemini_no_candidates_falls_back(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def fake_post(url, json=None, timeout=None, **kw):
        return _FakeResponse({"candidates": []})

    _install_fake_requests(monkeypatch, fake_post)
    findings = [_finding()]
    ai.explain_findings(findings, provider="gemini")
    assert findings[0].ai_explanation == ai.offline_explanation(_finding())


@pytest.mark.parametrize("provider", ["ollama", "gemini"])
def test_providers_never_raise(monkeypatch, provider):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def fake_post(url, json=None, timeout=None, **kw):
        raise ConnectionError("network down")

    _install_fake_requests(monkeypatch, fake_post)
    findings = [_finding()]
    # Must not propagate — a scan never breaks because an LLM was unavailable.
    ai.explain_findings(findings, provider=provider)
    assert findings[0].ai_explanation == ai.offline_explanation(_finding())
