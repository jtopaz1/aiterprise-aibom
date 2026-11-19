# Privacy

Source code never leaves the machine. The scanner does not execute what it scans: no unpickling,
no imports, no MCP server launches, no install scripts.

## What is sent, and when

| Mode | Sent to | What |
|---|---|---|
| `--offline` | nobody | nothing |
| default (online) | `api.osv.dev` | package names and exact versions, in POST bodies |
| default (online) | `pypi.org`, `registry.npmjs.org` | direct dependency names (registry paths) — existence and age checks; `--no-registry` turns this off |
| default (online) | `api.deps.dev` | the name and exact version of each pinned PyPI or npm package whose licence the lockfile does not record, direct or not (request paths) — package licences for the BOM; `--no-registry` turns this off too |
| logged in to SecDB | `secdb.aiterprise.net` | model-file SHA-256 hashes, package purls, and the first 8 hex digits of the SHA-256 of each private MCP URL (an MCP server's registry name too, once the scanner records one; none does yet); `--no-secdb` turns this off |
| `--byo virustotal=ENV_VAR` | `www.virustotal.com` | the SHA-256 of the model files and package archives the scan examined, with your own VirusTotal key — never file content, and nothing of it goes to AIterprise; see [Third-party providers](providers.md) |
| `--upload` | SecDB or your `--cloud` | the JSON report: component names, versions, hashes, findings — target reduced to its directory name, home paths to `~/…`; third-party provider findings are left out. Component names include the URLs of MCP servers and AI endpoints (an internal proxy's host among them; credentials, paths and queries are cut) and the paths of prompt files (never their text) |
| `report-fp` | SecDB | the rule id and your notes, after you consent |
| `login`, `status` | SecDB | your API key, to read the plan, limits and usage |
| `login --install` | SecDB | the scanner's name and version and the operating-system family (`windows`, `macos`, `linux`) — no credential, nothing about the user or the machine |
| `defs update` | SecDB, then the download addresses it returns | your credential, the channel and the release you already hold; then the bundle files are downloaded |
| `policy pull` | your `--cloud` | nothing but the API key (to authenticate) and the version you already hold |

`--offline --upload` is refused: an offline scan sends nothing. API keys go to a cloud only over
https (plain http is allowed to this machine, for local development); the same rule holds for a
`--byo` provider's base-URL override. A request that carries a key never follows a redirect: SecDB,
a cloud and a `--byo` provider each get the key at the one address you gave. A `--byo` key is read from an environment variable for the
run and is never stored, and a provider's answers are not cached.

There is no telemetry. The table report says so on its second line (`telemetry: off`). Every
request carries the User-Agent `aiterprise-scan/<version>` and no user or machine identifier.

## What is stored locally

| Path | Content |
|---|---|
| `~/.aiterprise/credentials.json` | the SecDB key or install token — DPAPI-encrypted on Windows, mode 0600 elsewhere |
| `~/.aiterprise/history/` | scans saved with `--save` or from the UI |
| `~/.aiterprise/defs/` | installed definition bundles |
| the cache directory | OSV, registry and deps.dev responses (`AITERPRISE_CACHE_DIR`) |
| `.aiterprise/` in a project | suppressions and baselines you create |

Secrets found by the scan are reported redacted and identified by a digest; the raw value is never
stored or sent.
