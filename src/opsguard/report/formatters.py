"""Render :class:`ScanResult` into several formats.

* ``terminal``  — rich, colourised console output for local use.
* ``markdown``  — a PR comment body (used by the GitHub Action).
* ``json``      — machine-readable, stable schema for downstream tooling.
* ``sarif``     — SARIF 2.1.0 for GitHub code scanning / the Security tab.
"""

from __future__ import annotations

import json
from typing import Dict, List

from opsguard import __version__
from opsguard.models import Finding, ScanResult, Severity

FORMATS = ("terminal", "markdown", "json", "sarif")

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}

_SEVERITY_COLOR = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=False)


# --------------------------------------------------------------------------- #
# Markdown (PR comment)
# --------------------------------------------------------------------------- #


def render_markdown(result: ScanResult) -> str:
    findings = result.sorted_findings()
    counts = result.counts_by_severity()
    lines: List[str] = []

    lines.append("## 🛡️ OpsGuard — Production Change Report")
    lines.append("")
    if not findings:
        lines.append("✅ **No risks detected.** This change looks safe to deploy.")
        lines.append("")
        lines.append(
            f"_Scanned {result.resources_scanned} resource(s) across "
            f"{len(result.files_scanned)} file(s)._"
        )
        return "\n".join(lines)

    # Summary badges
    badge_bits = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if counts[sev.name]:
            badge_bits.append(f"{_SEVERITY_EMOJI[sev]} **{counts[sev.name]} {sev.label}**")
    lines.append(" · ".join(badge_bits))
    lines.append("")

    top = findings[0]
    if top.severity >= Severity.HIGH:
        lines.append(
            f"> **Recommendation:** block this merge until the "
            f"{top.severity.label}-severity issues below are resolved."
        )
        lines.append("")

    # Summary table
    lines.append("| Severity | Rule | Resource | Issue |")
    lines.append("|---|---|---|---|")
    for f in findings:
        resource = f"`{f.resource}`"
        issue = f.title.replace("|", "\\|")
        lines.append(
            f"| {_SEVERITY_EMOJI[f.severity]} {f.severity.label} | `{f.rule_id}` | "
            f"{resource} | {issue} |"
        )
    lines.append("")

    # Details
    lines.append("### Details")
    lines.append("")
    for f in findings:
        lines.append(
            f"<details><summary>{_SEVERITY_EMOJI[f.severity]} "
            f"<strong>{f.severity.label}</strong> · {f.rule_id} · {f.title} "
            f"(risk {f.risk_score})</summary>"
        )
        lines.append("")
        lines.append(f"- **Resource:** `{f.resource}`")
        if f.resource.file:
            lines.append(f"- **File:** `{f.resource.file}`")
        lines.append(f"- **Change:** {f.change.value}")
        lines.append(f"- **What:** {f.message}")
        if f.impact:
            lines.append(f"- **Impact:** {f.impact}")
        if f.remediation:
            lines.append(f"- **Fix:** {f.remediation}")
        if f.affected:
            preview = ", ".join(f"`{a}`" for a in f.affected[:8])
            more = "" if len(f.affected) <= 8 else f" _(+{len(f.affected) - 8} more)_"
            lines.append(f"- **Blast radius ({len(f.affected)}):** {preview}{more}")
        if f.ai_explanation:
            lines.append(f"- **AI explanation:** {f.ai_explanation}")
        if f.references:
            refs = ", ".join(f"[ref]({r})" for r in f.references)
            lines.append(f"- **References:** {refs}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append(
        f"_OpsGuard v{__version__} · scanned {result.resources_scanned} resource(s) in "
        f"{len(result.files_scanned)} file(s)._"
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Terminal (rich)
# --------------------------------------------------------------------------- #


def render_terminal(result: ScanResult, use_color: bool = True) -> str:
    """Render to a string using rich. Returns plain text if rich is unavailable."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:  # pragma: no cover
        return _render_terminal_plain(result)

    import io

    console = Console(file=io.StringIO(), force_terminal=use_color, width=100, record=False)
    findings = result.sorted_findings()
    counts = result.counts_by_severity()

    header = Text("🛡  OpsGuard — Production Change Report", style="bold")
    console.print(header)

    if not findings:
        console.print(
            Panel(
                "No risks detected. This change looks safe to deploy.",
                style="green",
                title="PASS",
            )
        )
        console.print(
            f"Scanned {result.resources_scanned} resource(s) across "
            f"{len(result.files_scanned)} file(s)."
        )
        return console.file.getvalue()

    summary = Table.grid(padding=(0, 2))
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if counts[sev.name]:
            summary.add_row(
                Text(f"{sev.label}", style=_SEVERITY_COLOR[sev]),
                Text(str(counts[sev.name])),
            )
    console.print(summary)
    console.print()

    table = Table(show_lines=False, expand=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Resource")
    table.add_column("Issue")
    for f in findings:
        table.add_row(
            Text(f.severity.label, style=_SEVERITY_COLOR[f.severity]),
            str(f.risk_score),
            f.rule_id,
            str(f.resource),
            f.title,
        )
    console.print(table)
    console.print()

    for f in findings:
        body = Text()
        body.append(f.message + "\n\n")
        if f.impact:
            body.append("Impact: ", style="bold")
            body.append(f.impact + "\n")
        if f.remediation:
            body.append("Fix: ", style="bold")
            body.append(f.remediation + "\n")
        if f.affected:
            preview = ", ".join(f.affected[:6])
            more = "" if len(f.affected) <= 6 else f" (+{len(f.affected) - 6} more)"
            body.append("Blast radius: ", style="bold")
            body.append(f"{len(f.affected)} dependent(s): {preview}{more}\n")
        if f.ai_explanation:
            body.append("AI: ", style="bold")
            body.append(f.ai_explanation + "\n")
        title = f"[{f.severity.label}] {f.rule_id} · {f.resource}"
        console.print(Panel(body, title=title, border_style=_SEVERITY_COLOR[f.severity].split()[-1]))

    return console.file.getvalue()


def _render_terminal_plain(result: ScanResult) -> str:
    lines = ["OpsGuard — Production Change Report", ""]
    for f in result.sorted_findings():
        lines.append(f"[{f.severity.label}] {f.rule_id} {f.resource}: {f.title}")
        lines.append(f"    {f.message}")
        if f.remediation:
            lines.append(f"    Fix: {f.remediation}")
    if not result.findings:
        lines.append("No risks detected.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(result: ScanResult) -> str:
    findings = result.sorted_findings()

    # Build a unique rule descriptor set.
    rules_by_id: Dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in rules_by_id:
            rules_by_id[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "helpUri": f.references[0] if f.references else "https://github.com/mehwish786jnc/OpsGuard",
                "properties": {"security-severity": _security_severity(f.severity)},
            }

    results = [_sarif_result(f) for f in findings]

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpsGuard",
                        "informationUri": "https://github.com/mehwish786jnc/OpsGuard",
                        "version": __version__,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _security_severity(sev: Severity) -> str:
    # GitHub expects a numeric 0.0-10.0 string.
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[sev]


def _sarif_result(f: Finding) -> dict:
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.resource.file or "unknown"},
            "region": {"startLine": 1},
        }
    }
    message = f.message
    if f.remediation:
        message += f" Remediation: {f.remediation}"
    return {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": message},
        "locations": [location],
        "properties": {
            "severity": f.severity.name,
            "risk_score": f.risk_score,
            "blast_radius": f.affected,
        },
    }
