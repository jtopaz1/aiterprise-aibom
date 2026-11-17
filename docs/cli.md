# Command line

`aiterprise-scan <path>` is the same as `aiterprise-scan scan <path>`.

| Command | What it does |
|---|---|
| `scan [target]` | scan a repository, directory, model file, archive or BOM |
| `mcp [serve]` | judge MCP servers and agent skills only (skills are read inside the scanned directory, not from the machine's own folders); `mcp serve` runs the MCP tool over stdio |
| `bom [target]` | emit an AI-BOM without risk judgement (fast compliance mode) |
| `policy lint FILE` | validate a policy file |
| `policy pull [--cloud URL] [--out FILE]` | download the organisation's policy from an AIterprise cloud — see [Policy](policy.md#org-policy-from-the-cloud) |
| `defs status \| verify \| install \| update \| rollback` | definition data and signed bundles — see [Definition bundles](bundles.md) |
| `login` / `logout` / `status` | SecDB account — see [SecDB](secdb.md) |
| `upload report.json` | upload a JSON report to SecDB or an AIterprise cloud |
| `report-fp RULE` | report a false positive (with your consent) |
| `ui` | the local web UI — see [Local web UI](ui.md) |
| `version` | print the version |

## `scan`

| Flag | Meaning |
|---|---|
| `--bom FILE` | judge this CycloneDX (1.4–1.7) or SPDX 2.x JSON file |
| `--offline` | bundled definitions and cache only; no network |
| `--all-files` | do not honour `.gitignore` (only the one at the root of the target is read). Dependency and cache directories such as `node_modules`, `.venv` and `site-packages` are skipped either way, and a walk stops at 200,000 files with a note in the report |
| `--exclude GLOB` | skip paths matching GLOB, relative to the target (repeatable), e.g. `'tests/**'` |
| `--agent-configs` | also read this machine's agent and MCP configs and its skills folders |
| `--no-imports` | skip manifest-free import discovery |
| `--no-secrets` | skip the secret scan |
| `--max-vulns N` | at most N advisory findings per component |
| `--no-registry` | do not look packages up on PyPI/npm (existence and age); name checks still run |
| `--registry-all` | look up transitive dependencies on their registry too (default: direct only) |
| `--no-secdb` | do not consult SecDB even when logged in |
| `--upload` | upload the JSON report after the scan (SecDB Pro+, or `--cloud`); refused with `--offline` |
| `--project NAME` | project name for `--upload` (default: the target directory name) |
| `--cloud URL` | AIterprise cloud URL for `--upload` (or `AITERPRISE_CLOUD_URL`) |
| `--save` | keep this scan in the local history shown by `ui` |
| `--byo PROVIDER=ENV_VAR` | third-party enrichment with your own key, e.g. `virustotal=VT_API_KEY` (repeatable). `ENV_VAR` is the name of an environment variable holding the key, never the key itself — see [Third-party providers](providers.md) |
| `--format F` | `table`, `json`, `sarif`, `cyclonedx`, `html`, `markdown` (repeatable; default `table`). `markdown` is the new findings as a table for a pull-request comment, with every scanned string shown as code. The JSON report names its layout in `schema` (`aiterprise-report/1`) |
| `--out DIR` | write reports into this directory instead of stdout |
| `--emit-bom FILE` | also write the CycloneDX AI-BOM to FILE |
| `--cdx-version 1.6\|1.7` | CycloneDX version (default 1.7) |
| `--inventory` | list every discovered component in the table |
| `--show-suppressed` | show suppressed and baselined findings |
| `--fail-on SEV` | exit 1 if any new finding is at least this severe (`none` never fails; default: policy, else `high`) |
| `--policy FILE` | policy file (default: `aibom.policy.yaml` in the target) |
| `--snyk FILE` | import suppressions from a `.snyk` file (30-day default expiry) |
| `--baseline FILE` | only findings not in this baseline fail the gate |
| `--write-baseline FILE` | write the current findings as a baseline |

`mcp` takes the same report and gate flags, plus `--path DIR` (where to look for project-level
configs), `--agent-configs` and `--offline`.

## Other commands

| Command | Flags |
|---|---|
| `bom [target]` | `--out FILE` (default: stdout), `--cdx-version` (`1.6` or `1.7`; default 1.7), `--all-files` |
| `policy pull` | `--cloud URL`, `--out FILE` (default: `aibom.policy.yaml` in the current directory) |
| `defs verify DIR`, `defs install DIR` | `--root-key FILE` |
| `defs update` | `--root-key FILE`, `--channel NAME` (default: your account's), `--signing-keys URL` (default: next to the manifest) |
| `login` | `--key-stdin` (read the key from stdin, for CI) or `--install` (register an anonymous install token instead of using an API key) |
| `report-fp RULE` | `--notes TEXT`, `--yes` (consent given) |
| `upload report.json` | `--project NAME`, `--cloud URL`. A report without `schema` (written by an older version) is accepted; one that names another schema is refused |
| `ui` | `--port N` (default: a free port), `--no-browser` (print the link instead of opening a browser) |

`aiterprise-scan --version` prints the version, like the `version` command.

## Environment

| Variable | Meaning |
|---|---|
| `AITERPRISE_API_KEY` | SecDB API key (CI); takes precedence over a saved key |
| `AITERPRISE_HOME` | where credentials, history and installed bundles live (default `~/.aiterprise`) |
| `AITERPRISE_CACHE_DIR` | OSV and registry response cache |
| `AITERPRISE_SECDB_URL` | SecDB base URL (default `https://secdb.aiterprise.net`) |
| `AITERPRISE_CLOUD_URL` | AIterprise cloud URL for uploads and `policy pull` (https, or http to this machine only) |
| `AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS` | VirusTotal lookups per scan with `--byo` (default 4, the public key's per-minute limit) |
| `AITERPRISE_VIRUSTOTAL_URL` | VirusTotal base URL for `--byo` (a proxy or test server; https, or http to this machine only) |
| `AITERPRISE_ROOT_KEY` | minisign root public key file for bundle verification |
| `AITERPRISE_DEFS=bundled` | ignore installed bundles and use the wheel's data |

## Exit codes

`0` pass · `1` policy failure · `2` error or incomplete scan. An unreachable source (OSV, a
registry) makes the scan incomplete; `--offline` does not.
