# AIterprise AIBOM Scanner — `aiterprise-scan`

The open-source AI supply-chain scanner you can run offline: an AI-BOM with teeth. One command walks
a repository, a model file, an agent configuration or a third-party AI-BOM, inventories every AI
component, and judges it — every finding carries its evidence.

```bash
pipx install aiterprise-scan        # or: pip install .
aiterprise-scan .                   # scan the current repository
```

Apache-2.0 · zero runtime dependencies (standard library only) · Python 3.11+

## What it finds

| Area | What is judged | Rule ids |
|---|---|---|
| Packages | Known-malicious versions (OSV `MAL-` snapshot, withdrawn records excluded); ranges that admit a malicious version | `ait.pkg.malicious*` |
| Vulnerabilities | OSV advisories per exact version, alias-deduplicated, fix versions; CISA KEV upgrades to critical | `ait.vuln.*` |
| Model files | Pickle opcodes (raw and zip-wrapped, protocol 0–5) with dangerous callables, safetensors/GGUF/ONNX/HDF5/Keras/TFLite inventory, Keras `Lambda`, ONNX custom ops, GGUF chat-template injection, malformed containers | `ait.model.*` |
| MCP servers | Every agent's config (Claude Desktop/Code, Cursor, VS Code, Codex, Windsurf, Gemini): dangerous commands, poisoned descriptions, literal secrets, scope — **without launching anything** | `ait.mcp.*` |
| Agent skills | `SKILL.md` trees, Claude Code plugins/commands: instruction poisoning, install-script commands, risk score | `ait.skill.*` |
| Licences | Model and dataset licence verdicts (Llama, Gemma, OpenRAIL, Mistral, Qwen, DBRX, DeepSeek, Falcon, CC-BY-NC, …) against your `use_context` — advisory, not legal advice | `ait.licence.*` |
| Secrets | AI-provider keys in configs and code, reported redacted | `ait.secret.*` |

Inputs: `requirements*.txt`, `pyproject.toml` (PEP 621 + Poetry), `Pipfile(.lock)`, `poetry.lock`,
`uv.lock`, `environment.yml`, `package.json`, `package-lock.json` v1–v3, `pnpm-lock.yaml`,
`yarn.lock`; Python/JS imports and notebooks (manifest-free discovery); CycloneDX 1.4–1.7 and SPDX
JSON BOMs — including AI-BOMs from cdxgen, Snyk and OWASP generators. A lockfile always wins over a
manifest, and a range is never treated as an exact version.

## Usage

```bash
aiterprise-scan .                                   # table report on stdout, exit 0/1/2
aiterprise-scan . --offline                         # bundled definitions + cache only, no network
aiterprise-scan scan --bom cdxgen-aibom.json        # judge someone else's AI-BOM
aiterprise-scan . --format sarif --out reports/     # report.sarif for GitHub code scanning
aiterprise-scan . --emit-bom aibom.cdx.json         # CycloneDX 1.7 AI-BOM with findings attached
aiterprise-scan mcp --agent-configs                 # this machine's MCP servers and skills
aiterprise-scan bom . --out aibom.cdx.json          # inventory only (fast compliance mode)
aiterprise-scan . --write-baseline .aiterprise/baseline.json   # adopt gating without fixing everything
aiterprise-scan policy lint aibom.policy.yaml
aiterprise-scan defs status
```

Exit codes: `0` clean · `1` policy failure (`--fail-on`, default `high`) · `2` error or incomplete scan.

## Policy

`aibom.policy.yaml` in the scanned directory (or `--policy FILE`):

```yaml
version: 1
use_context: commercial          # commercial | internal | research | non-profit
fail_on: [critical, high]
ignore:
  - rule: ait.pkg.malicious-unpinned
    paths: ["experiments/**"]
allow_packages: ["pkg:pypi/openai@>=1.40"]
deny_packages: ["pkg:pypi/litellm@1.82.7"]
deny_model_licences: [cc-by-nc-4.0]
suppressions:                    # expiry is mandatory
  - finding: 1a2b3c4d5e6f7a8b    # fingerprint, advisory id or rule id
    until: 2027-06-30
    reason: vendor patch scheduled
    approved_by: security@company
baseline: .aiterprise/baseline.json
```

A known-malicious finding is never silenced by `ignore` or `allow_packages`; only an explicit,
expiring suppression of that exact finding accepts it. `.snyk` ignore files can be imported with
`--snyk .snyk` (30-day default expiry).

## CI

GitHub Action (uploads SARIF, then gates):

```yaml
- uses: jtopaz1/aiterprise-aibom/action@main
  with:
    fail-on: high
```

pre-commit:

```yaml
- repo: https://github.com/jtopaz1/aiterprise-aibom
  rev: main
  hooks: [{ id: aiterprise-scan }]
```

## Principles

- **Local-first.** Source never leaves the machine. Online mode sends package names and versions to
  OSV in POST bodies; `--offline` sends nothing.
- **Never execute what we scan.** No unpickling, no imports, no MCP server launches.
- **"No match" is not "never checked".** Every report lists which sources were consulted and how
  many items had data; unverified checks are reported as unverified, never as safe.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -p "test_*.py"
python tools/build_malicious.py --zip PyPI-all.zip --zip npm-all.zip --replace   # refresh the MAL snapshot
python tools/build_kev.py --url                                                  # refresh CISA KEV
aiterprise-scan defs status                                                      # what is bundled, with input hashes
```

Bundled definitions (2026-11-14): 235,476 OSV `MAL-` records for npm and PyPI (withdrawn records
excluded) and 1,781 CISA KEV CVEs. Details and refresh steps: [docs/STATUS.md](docs/STATUS.md).

Design of record: `aiterprise-doc/13-APP-AIBOM.md` (AI2).
