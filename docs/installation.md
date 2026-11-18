# Installation

OpsGuard is a Python package (3.9+) with a small, pure-Python dependency set.

## From PyPI

```bash
pip install opsguard
```

## With AI explanation support

The optional `ai` extra adds `requests` for the Ollama/Gemini providers. The
default `offline` provider needs no extra dependencies.

```bash
pip install "opsguard[ai]"
```

## From source

```bash
git clone https://github.com/mehwish786jnc/OpsGuard && cd OpsGuard
pip install -e ".[dev]"
```

## Verify

```bash
opsguard --version
opsguard rules        # list every built-in rule
```

## Requirements

| | |
|---|---|
| Python | 3.9, 3.10, 3.11, 3.12 |
| Core deps | PyYAML, networkx, typer, rich |
| Optional | requests (`ai` extra) |

No network access is required for a scan unless you explicitly enable a remote
AI provider — OpsGuard runs happily in air-gapped CI.
