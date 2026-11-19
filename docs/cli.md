# Command line

`aiterprise-scan <path>` is the same as `aiterprise-scan scan <path>`.

| Command | What it does |
|---|---|
| `scan [target]` | scan a repository, directory, model file, archive or BOM |
| `mcp [serve]` | judge MCP servers and agent skills only (skills inside the scanned directory; with `--agent-configs` also the machine's skills folders); `mcp serve` runs the MCP tool over stdio |
| `bom [target]` | emit an AI-BOM without risk judgement (fast compliance mode) |
| `policy lint [FILE]` | validate a policy file (default: the current directory's `aibom.policy.yaml`, `.yml`, `.json` or `.aiterprise/policy.yaml`) |
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
| `--bom FILE` | judge this CycloneDX (1.4–1.7) or SPDX 2.x JSON file (repeatable) |
| `--offline` | bundled definitions and cache only; no network |
| `--all-files` | do not honour `.gitignore` (only the one at the root of the target is read). Dependency and cache directories such as `node_modules`, `.venv` and `site-packages` are skipped either way, and a walk stops at 200,000 files with a note in the report |
| `--exclude GLOB` | skip paths matching GLOB, relative to the target (repeatable), e.g. `'tests/**'` |
| `--agent-configs` | also read this machine's agent and MCP configs and its skills folders |
| `--no-imports` | skip manifest-free import discovery |
| `--no-secrets` | skip the secret scan |
| `--max-vulns N` | at most N advisory findings per component |
| `--no-registry` | do not look packages up on PyPI/npm (existence and age) or on deps.dev (licences); name checks still run |
| `--registry-all` | look up transitive dependencies on their registry too (default: direct only) |
| `--no-secdb` | do not consult SecDB even when logged in |
| `--upload` | upload the JSON report after the scan (SecDB Pro+, or `--cloud`); refused with `--offline` |
| `--project NAME` | project name for `--upload` (default: the target directory name) |
| `--cloud URL` | AIterprise cloud URL for `--upload` (or `AITERPRISE_CLOUD_URL`) |
| `--save` | keep this scan in the local history shown by `ui` |
| `--no-cache` | do not reuse or keep per-file results between scans (see [Re-scans](#re-scans)) |
| `--byo PROVIDER=ENV_VAR` | third-party enrichment with your own key, e.g. `virustotal=VT_API_KEY` (repeatable). `ENV_VAR` is the name of an environment variable holding the key, never the key itself — see [Third-party providers](providers.md) |
| `--defs-version REL_ID` | use this installed definitions release (`rel_…`), or `bundled` for the data shipped with this version. The scan exits 2 without running if the release is not installed or a file changed since it was — see [Pinning a release](bundles.md#pinning-a-release) |
| `--format F` | `table`, `json`, `sarif`, `cyclonedx`, `html`, `markdown` (repeatable; default `table`). `markdown` is the new findings as a table for a pull-request comment, with every scanned string shown as code; `compact` is one `path:line: error|warning|info: title [severity rule]` line per new finding, for editor problem matchers; `codequality` is GitLab's Code Quality report. See [Editors and CI](integrations.md). The JSON report names its layout in `schema` (`aiterprise-report/1`) |
| `--out PATH` | write reports into this directory instead of stdout, named `report.json`, `report.sarif`, `aibom.cdx.json`, `report.html`, … With one `--format`, a path ending in `.json`, `.sarif`, `.html`, `.htm`, `.md` or `.txt` is the report file itself (`--format sarif --out results.sarif`), unless a directory of that name exists already |
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
configs), `--agent-configs`, `--offline` and `--defs-version`.

## Other commands

| Command | Flags |
|---|---|
| `bom [target]` | `--out FILE` (default: stdout), `--cdx-version` (`1.6` or `1.7`; default 1.7), `--all-files`, `--no-cache` |
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
| `AITERPRISE_CACHE_DIR` | OSV and registry response cache, and the per-file results of earlier scans in its `scan` folder (default `~/.aiterprise/cache`) |
| `AITERPRISE_SECDB_URL` | SecDB base URL (default `https://secdb.aiterprise.net`) |
| `AITERPRISE_CLOUD_URL` | AIterprise cloud URL for uploads and `policy pull` (https, or http to this machine only) |
| `AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS` | VirusTotal lookups per scan with `--byo` (default 4, the public key's per-minute limit) |
| `AITERPRISE_VIRUSTOTAL_URL` | VirusTotal base URL for `--byo` (a proxy or test server; https, or http to this machine only) |
| `AITERPRISE_ROOT_KEY` | minisign root public key file for bundle verification |
| `AITERPRISE_DEFS` | `bundled`: ignore installed bundles and use the wheel's data; `rel_…`: pin that installed release, like `--defs-version` (which wins) |

## Package licences

A package's licence goes into the BOM (CycloneDX `licenses`, marked as declared), the JSON report
(`licence`) and the HTML report. Offline it comes from the lockfile: npm's `package-lock.json`
(v2 and v3) records each package's licence. Online, each pinned PyPI or npm package still without
one is looked up on [deps.dev](https://deps.dev), one request per name and version, cached like the
registry answers. When deps.dev lists several licences for a version they are joined with `AND`.
A licence deps.dev cannot map to an SPDX id comes back as `non-standard`: the BOM leaves those
empty and a note in the report names them. The report's coverage has a `deps.dev` entry with the
number of versions looked up and how many had a licence; a failed lookup is counted there and
makes the scan exit 2, like any source that did not answer. `--offline` and `--no-registry` turn
the lookups off; `bom` never goes online, so its BOM has the lockfile licences only. A package's
licence is judged only against the policy's `allow_package_licences` and `deny_package_licences`
(see [Package licences in the policy](policy.md#package-licences)).

## Re-scans

`scan` and `bom` keep what four analyzers found in each file (imports, endpoints and vector stores,
model and dataset references, secrets), under the file's SHA-256, in `AITERPRISE_CACHE_DIR/scan`
(one file per analyzer and target). The next scan of the same target still reads every file, but
takes an unchanged file's results from there instead of analysing it again, and the report says how
many it took (`file cache: … per-file results are from an earlier scan`). A secret is kept as the
report shows it: rule, line, redacted preview and an 8-character digest, never the value. Whether a
model id in code names a folder of the tree is checked again on every scan; notebooks are always
analysed again.
Results are used only by the same build of the scanner (its version and every file of the
package) with the same definitions release; anything else starts empty. A target not scanned for
30 days is forgotten, and at most 256 such files are kept. Judging (advisories, malicious
packages, policy) runs in full on every scan. `--no-cache` turns this off.

The folder is trusted: whoever can write it can hide what a file holds from later scans. Do not
share it across a trust boundary, for example in a CI cache that untrusted pull requests fill.

## Exit codes

`0` pass · `1` policy failure · `2` error or incomplete scan. An unreachable source (OSV, a
registry) makes the scan incomplete; `--offline` does not.
