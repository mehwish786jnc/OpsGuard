"""OpsGuard command-line interface.

Examples::

    opsguard scan ./k8s
    opsguard scan ./k8s --tf-plan tfplan.json --format markdown
    opsguard scan ./infra --fail-on high --format sarif -o results.sarif
    opsguard rules
"""

# NOTE: intentionally NO ``from __future__ import annotations`` here — Typer
# evaluates type hints at runtime to build the CLI.

import sys
from pathlib import Path
from typing import List, Optional

import typer

from opsguard import __version__
from opsguard import rules as rules_pkg
from opsguard.engine import ScanConfig, analyze
from opsguard.models import ScanResult, Severity
from opsguard.report import formatters

app = typer.Typer(
    name="opsguard",
    help="Catch the change before it breaks production.",
    add_completion=False,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"OpsGuard {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """OpsGuard — production change intelligence."""


def _render(result: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return formatters.render_json(result)
    if fmt == "markdown":
        return formatters.render_markdown(result)
    if fmt == "sarif":
        return formatters.render_sarif(result)
    return formatters.render_terminal(result)


@app.command()
def scan(
    paths: List[Path] = typer.Argument(
        None,
        help="Files or directories containing Kubernetes manifests to scan.",
    ),
    tf_plan: Optional[List[Path]] = typer.Option(
        None, "--tf-plan", help="Terraform plan JSON file(s) (terraform show -json).",
    ),
    fmt: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, markdown, json, sarif.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write the report to a file instead of stdout.",
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Exit non-zero if a finding at/above this severity exists "
        "(info, low, medium, high, critical, or 'never').",
    ),
    min_severity: str = typer.Option(
        "info", "--min-severity", help="Hide findings below this severity.",
    ),
    disable: Optional[List[str]] = typer.Option(
        None, "--disable", help="Rule id(s) to disable, e.g. --disable K8S-IMG-001.",
    ),
    ai: bool = typer.Option(
        False, "--ai/--no-ai", help="Attach AI explanations to findings.",
    ),
    ai_provider: str = typer.Option(
        "offline", "--ai-provider", help="AI provider: offline, ollama, gemini.",
    ),
    ai_model: Optional[str] = typer.Option(
        None, "--ai-model", help="Model name for the AI provider.",
    ),
) -> None:
    """Scan infrastructure changes and report production risks."""
    paths = paths or []
    if not paths and not tf_plan:
        typer.secho("Nothing to scan. Provide a path and/or --tf-plan.", fg="red", err=True)
        raise typer.Exit(code=2)

    if fmt not in formatters.FORMATS:
        typer.secho(
            f"Unknown format '{fmt}'. Choose from: {', '.join(formatters.FORMATS)}.",
            fg="red",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        min_sev = Severity.parse(min_severity)
    except ValueError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(code=2) from exc

    config = ScanConfig(
        paths=[str(p) for p in paths],
        tf_plans=[str(p) for p in (tf_plan or [])],
        disabled_rules=set(disable or []),
        min_severity=min_sev,
        with_ai=ai,
        ai_provider=ai_provider,
        ai_model=ai_model,
    )

    result = analyze(config)

    report = _render(result, fmt)
    if output:
        output.write_text(report, encoding="utf-8")
        typer.secho(f"Report written to {output}", fg="green", err=True)
    else:
        # Use plain echo so piped output (markdown/json/sarif) stays clean.
        typer.echo(report)

    for err in result.errors:
        typer.secho(f"warning: {err}", fg="yellow", err=True)

    # --- Exit code / gating ------------------------------------------------
    if fail_on.lower() == "never":
        raise typer.Exit(code=0)
    try:
        gate = Severity.parse(fail_on)
    except ValueError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(code=2) from exc

    max_sev = result.max_severity()
    if max_sev is not None and max_sev >= gate:
        typer.secho(
            f"OpsGuard: failing — found {max_sev.label}-severity finding(s) "
            f"at or above the '{gate.label}' gate.",
            fg="red",
            err=True,
        )
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


@app.command()
def rules() -> None:
    """List all built-in rules."""
    k8s = rules_pkg.get_kubernetes_rules()
    tf = rules_pkg.get_terraform_rules()
    typer.secho("Kubernetes rules", bold=True)
    for r in k8s:
        typer.echo(f"  {r.id:<18} {r.severity.label:<9} {r.title}")
    typer.secho("\nTerraform rules", bold=True)
    for r in tf:
        typer.echo(f"  {r.id:<18} {r.severity.label:<9} {r.title}")
    typer.echo(f"\nTotal: {len(k8s) + len(tf)} rules.")


def main() -> None:  # pragma: no cover - console entry wrapper
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
