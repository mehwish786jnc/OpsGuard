"""AI explanations for findings.

Architectural principle (important):
    AI **never** decides whether something is a risk. The deterministic rules
    already did that. AI only turns a finding into a clearer, friendlier
    explanation and remediation narrative.

Providers:
    * ``offline`` (default) — no network, fully deterministic. Composes a clear
      explanation from the finding's own fields. This keeps OpsGuard usable in
      air-gapped CI and makes tests reproducible.
    * ``ollama`` — calls a local Ollama server (``OLLAMA_HOST``, default
      http://localhost:11434). Requires the ``requests`` extra.
    * ``gemini`` — calls Google Gemini (``GEMINI_API_KEY``). Requires ``requests``.

Any provider failure falls back to the offline explanation, so a scan never
breaks because an LLM was unavailable.
"""

from __future__ import annotations

import os
from typing import List, Optional

from opsguard.models import Finding

_SYSTEM_PROMPT = (
    "You are OpsGuard, a production safety reviewer. You are given a security or "
    "reliability finding that has ALREADY been confirmed by deterministic rules. "
    "Do NOT second-guess whether it is a real issue. In 2-4 short sentences, "
    "explain the risk to an engineer reviewing a pull request and give concrete "
    "remediation steps. Be specific and practical. Do not use markdown headings."
)


def offline_explanation(finding: Finding) -> str:
    parts = [finding.message.strip()]
    if finding.impact:
        parts.append(f"Why it matters: {finding.impact.strip()}")
    if finding.remediation:
        parts.append(f"How to fix: {finding.remediation.strip()}")
    if finding.affected:
        preview = ", ".join(finding.affected[:5])
        more = "" if len(finding.affected) <= 5 else f" (+{len(finding.affected) - 5} more)"
        parts.append(f"Blast radius — dependent resources: {preview}{more}.")
    return " ".join(parts)


def _finding_prompt(finding: Finding) -> str:
    affected = ", ".join(finding.affected) if finding.affected else "none detected"
    return (
        f"Finding: {finding.title}\n"
        f"Rule: {finding.rule_id}\n"
        f"Severity: {finding.severity.name}\n"
        f"Resource: {finding.resource}\n"
        f"Change type: {finding.change.value}\n"
        f"Detail: {finding.message}\n"
        f"Known impact: {finding.impact}\n"
        f"Suggested remediation: {finding.remediation}\n"
        f"Dependent resources (blast radius): {affected}\n"
    )


def _ollama_explain(finding: Finding, model: str, timeout: float) -> Optional[str]:
    try:
        import requests
    except ImportError:
        return None
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        resp = requests.post(
            f"{host}/api/generate",
            json={
                "model": model,
                "system": _SYSTEM_PROMPT,
                "prompt": _finding_prompt(finding),
                "stream": False,
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (data.get("response") or "").strip()
        return text or None
    except Exception:  # noqa: BLE001 - any failure falls back to offline
        return None


def _gemini_explain(finding: Finding, model: str, timeout: float) -> Optional[str]:
    try:
        import requests
    except ImportError:
        return None
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={api_key}"
    )
    try:
        resp = requests.post(
            url,
            json={
                "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
                "contents": [{"parts": [{"text": _finding_prompt(finding)}]}],
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return None
        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts).strip()
        return text or None
    except Exception:  # noqa: BLE001
        return None


def explain_findings(
    findings: List[Finding],
    provider: str = "offline",
    model: Optional[str] = None,
    timeout: float = 30.0,
) -> None:
    """Populate ``ai_explanation`` on each finding in place.

    Unknown providers and any runtime error degrade gracefully to the offline
    explanation.
    """
    provider = (provider or "offline").lower()
    for finding in findings:
        text: Optional[str] = None
        if provider == "ollama":
            text = _ollama_explain(finding, model or "llama3", timeout)
        elif provider == "gemini":
            text = _gemini_explain(finding, model or "gemini-1.5-flash", timeout)
        finding.ai_explanation = text or offline_explanation(finding)
