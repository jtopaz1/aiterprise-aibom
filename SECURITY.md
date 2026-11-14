# Security policy

## Reporting a vulnerability

Please report vulnerabilities in `aiterprise-scan` privately through GitHub's
"Report a vulnerability" (Security Advisories) on this repository. Do not open a public issue.
We aim to acknowledge reports within 3 business days.

## How the scanner protects you

- Scanned content is treated as hostile. The scanner never unpickles, imports, loads or executes
  scanned files, and never launches or connects to MCP servers, hooks or skill scripts.
- Parsers are bounded: size caps, zip-slip and zip-bomb guards, no symlink following.
- `--offline` makes no network calls. Online mode sends package names and versions to OSV
  (`api.osv.dev`) in POST bodies; it never uploads source code.
- Secrets found during a scan are only ever reported in redacted form.
- Telemetry is off. There is no telemetry code in this release.
