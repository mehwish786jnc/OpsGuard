# Security Policy

## Supported versions

OpsGuard is pre-1.0. Security fixes are applied to the latest released version
on PyPI and the `main` branch.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's security advisories:
<https://github.com/mehwish786jnc/OpsGuard/security/advisories/new>

Please include:

- A description of the issue and its impact
- Steps to reproduce (a minimal manifest/plan if relevant)
- The OpsGuard and Python versions affected

We aim to acknowledge reports within **5 business days** and will keep you
updated as we investigate and ship a fix. Responsible disclosure is appreciated —
we'll credit you in the release notes unless you prefer to remain anonymous.

## Scope

OpsGuard parses untrusted infrastructure files. Of particular interest:

- Parsing issues (YAML/JSON) that could cause crashes, resource exhaustion, or
  code execution.
- Any path where a scanned file could lead to unintended file access or network
  calls.

Note: OpsGuard's deterministic rules are advisory. A missed finding (false
negative) is a bug, not a vulnerability, unless it stems from a parsing flaw.
