#!/usr/bin/env python3
"""Regenerate the terminal demo asset embedded in the README.

Runs OpsGuard against the bundled risky examples and exports the rendered
report to ``assets/demo.svg`` using Rich's SVG exporter. Deterministic — no
network, no screen recorder — so the image stays in sync with real output.

    python scripts/gen_demo.py
    make demo
"""

from __future__ import annotations

import os
import sys

# Make the package importable when run from a source checkout.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from rich.console import Console  # noqa: E402

from opsguard.engine import ScanConfig, analyze  # noqa: E402
from opsguard.report.formatters import render_to_console  # noqa: E402

OUTPUT = os.path.join(ROOT, "assets", "demo.svg")


def main() -> int:
    config = ScanConfig(
        paths=[os.path.join(ROOT, "examples", "risky-k8s")],
        tf_plans=[os.path.join(ROOT, "examples", "terraform", "tfplan.json")],
    )
    result = analyze(config)

    console = Console(record=True, force_terminal=True, width=100)
    render_to_console(result, console)

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    console.save_svg(OUTPUT, title="opsguard scan")
    print(f"Wrote {OUTPUT} ({len(result.findings)} findings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
