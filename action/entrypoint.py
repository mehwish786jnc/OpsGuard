#!/usr/bin/env python3
"""GitHub Action entrypoint for OpsGuard.

Runs a scan using the installed ``opsguard`` package, writes a Markdown report
and optional SARIF file, posts (or updates) a single sticky comment on the pull
request, and sets the job's exit code based on the configured gate.

All configuration comes from ``INPUT_*`` environment variables set by the
composite action. The script only uses the standard library plus ``opsguard``
itself, so no extra dependencies are required at runtime.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import List, Optional

from opsguard.engine import ScanConfig, analyze
from opsguard.models import Severity
from opsguard.report import render_markdown, render_sarif

STICKY_MARKER = "<!-- opsguard-report -->"


def _inp(name: str, default: str = "") -> str:
    return os.environ.get(f"INPUT_{name.upper().replace('-', '_')}", default).strip()


def _split(value: str) -> List[str]:
    return [p.strip() for p in value.replace(",", "\n").splitlines() if p.strip()]


def _set_output(name: str, value: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def _write_summary(markdown: str) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")


def _pr_number() -> Optional[int]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        return None
    try:
        with open(event_path, "r", encoding="utf-8") as handle:
            event = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    pr = event.get("pull_request") or {}
    number = pr.get("number")
    return int(number) if number is not None else None


def _api_request(method: str, url: str, token: str, payload: Optional[dict] = None) -> Optional[dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "opsguard-action")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - trusted GitHub API
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        sys.stderr.write(f"GitHub API {method} {url} failed: {exc.code} {exc.reason}\n")
    except urllib.error.URLError as exc:
        sys.stderr.write(f"GitHub API request error: {exc}\n")
    return None


def _post_sticky_comment(markdown: str, token: str) -> None:
    repo = os.environ.get("GITHUB_REPOSITORY")
    pr = _pr_number()
    if not repo or not pr or not token:
        sys.stderr.write("Not a PR context or missing token; skipping comment.\n")
        return

    body = f"{STICKY_MARKER}\n{markdown}"
    base = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"

    existing = _api_request("GET", base + "?per_page=100", token) or []
    comment_id = None
    if isinstance(existing, list):
        for comment in existing:
            if STICKY_MARKER in (comment.get("body") or ""):
                comment_id = comment.get("id")
                break

    if comment_id:
        url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
        _api_request("PATCH", url, token, {"body": body})
    else:
        _api_request("POST", base, token, {"body": body})


def main() -> int:
    paths = _split(_inp("paths", "."))
    tf_plans = _split(_inp("tf-plan"))
    fail_on = _inp("fail-on", "high").lower()
    min_severity = _inp("min-severity", "info")
    comment = _inp("comment", "true").lower() == "true"
    sarif_file = _inp("sarif-file")
    with_ai = _inp("ai", "false").lower() == "true"
    ai_provider = _inp("ai-provider", "offline")
    ai_model = _inp("ai-model") or None
    token = _inp("token") or os.environ.get("GITHUB_TOKEN", "")

    config = ScanConfig(
        paths=paths,
        tf_plans=tf_plans,
        min_severity=Severity.parse(min_severity),
        with_ai=with_ai,
        ai_provider=ai_provider,
        ai_model=ai_model,
    )
    result = analyze(config)

    markdown = render_markdown(result)
    _write_summary(markdown)

    if sarif_file:
        with open(sarif_file, "w", encoding="utf-8") as handle:
            handle.write(render_sarif(result))
        sys.stderr.write(f"SARIF written to {sarif_file}\n")

    if comment:
        _post_sticky_comment(markdown, token)

    max_sev = result.max_severity()
    counts = result.counts_by_severity()
    _set_output("total-findings", str(len(result.findings)))
    _set_output("max-severity", max_sev.name if max_sev else "NONE")
    _set_output("critical", str(counts["CRITICAL"]))
    _set_output("high", str(counts["HIGH"]))

    for err in result.errors:
        sys.stderr.write(f"warning: {err}\n")

    if fail_on == "never" or max_sev is None:
        print(f"OpsGuard: {len(result.findings)} finding(s). Gate passed.")
        return 0

    gate = Severity.parse(fail_on)
    if max_sev >= gate:
        sys.stderr.write(
            f"OpsGuard: FAIL — {max_sev.label} finding(s) at/above the '{gate.label}' gate.\n"
        )
        return 1

    print(f"OpsGuard: {len(result.findings)} finding(s), highest {max_sev.label}. Gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
