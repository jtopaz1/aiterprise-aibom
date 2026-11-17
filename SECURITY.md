# Security policy

## Reporting a vulnerability

Please report vulnerabilities in `aiterprise-scan` privately through GitHub's
"Report a vulnerability" (Security Advisories) on this repository. Do not open a public issue.
We aim to acknowledge reports within 3 business days.

## Disclosure policy

- **In scope:** the scanner, its GitHub Action, pre-commit hook and CI templates, and the
  definition data and signed bundles in this repository. A crafted file, package or agent config
  that makes the scanner run code, read or write outside what it scans, follow a link out of an
  archive, hang or exhaust memory, print a secret unredacted, or post scanned text into a
  pull-request comment as live Markdown is a vulnerability.
- **Evasions:** an input that a rule should catch and does not is a detection gap, not a
  vulnerability in the scanner. Report it privately all the same: a published evasion helps
  attackers before the rule is fixed.
- **False positives** are not security issues: use `aiterprise-scan report-fp` or a public issue.
- **Coordinated disclosure, 90 days by default.** We publish a security advisory when the fix
  ships, crediting you unless you prefer otherwise. If no fix has shipped 90 days after your
  report, you may publish. We disclose sooner when a fix ships sooner, and later only by
  agreement with you, for example when the fix depends on a third party.
- **Supported versions:** the latest release. Before 1.0, fixes go into the next release only.

## How the scanner protects you

- Scanned content is treated as hostile. The scanner never unpickles, imports, loads or executes
  scanned files, and never launches or connects to MCP servers, hooks or skill scripts.
- Parsers are bounded: size caps, zip-slip and zip-bomb guards, no symlink following.
- `--offline` makes no network calls. Online mode sends package names and versions to OSV
  (`api.osv.dev`) and the PyPI and npm registries; signed in to SecDB, or with `--byo`, it also
  sends hashes and package identifiers. `docs/privacy.md` lists every case. Source code is never
  uploaded.
- Secrets found during a scan are only ever reported in redacted form.
- Telemetry is off. There is no telemetry code in this release.
