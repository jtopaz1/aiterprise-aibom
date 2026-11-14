# Implementation status — `aiterprise-scan` 0.1.0 (rewrite)

Updated 2026-11-14. Design of record: `aiterprise-doc/13-APP-AIBOM.md` (AI2). This is a clean-room
rewrite of the OSS engine; the v0.2.0 code described in that document's Appendix H was not available,
so this table restates Appendix H.1 against what exists in this repository today.

## Built

| Capability (plan item) | Module / command | Status |
|---|---|---|
| One-command scan of a repo, file, BOM or agent config | `aiterprise-scan scan [<path>]`, bare `aiterprise-scan <path>` | working |
| Repository discovery (W2): requirements, pyproject (PEP 621 + Poetry), Pipfile(.lock), poetry.lock, uv.lock, environment.yml, package.json, package-lock v1–v3, pnpm-lock v5/v6/v9, yarn.lock v1/berry; Python/JS imports and notebooks. Lockfile wins over manifest; a range is never an exact version | `discover.py` | working |
| Component taxonomy (§4.2) | `data/ait/taxonomy.json`, `taxonomy.py` | working (first-party, curated) |
| BOM ingest (C09): CycloneDX 1.4–1.7 (nested), SPDX 2.x JSON, UTF-8/UTF-16 with or without BOM; versionless components marked unjudgeable | `ingest.py` | working |
| Known-malicious versions (C14): OSV `MAL-` snapshot; exact, all-versions, range-admits-malicious, unpinned. A match on a withdrawn record (bundled, or seen live on OSV) is reported with status `withdrawn` — same fingerprint, never active, never dropped (§4.3) | `intel_malicious.py`, `data/ait/malicious-versions.json.gz` | working — 235,476 records (npm 223,456 · PyPI 12,020) + 363 withdrawn kept apart, built 2026-11-14 |
| Vulnerabilities (C19): OSV querybatch → per-advisory details, cached, alias de-duplication, CVSS v3 base score, fix-version advice preferring final releases | `vulns.py`, `net.py`, `cache.py` | working (verified live against api.osv.dev) |
| Exploitation priority (C20): CISA KEV upgrades to critical | `vulns.py`, `data/ait/kev.json` | working — 1,781 CVEs, catalog 2026.11.13 (verified live: three litellm 1.82.7 CVEs upgrade to critical) |
| Model files (C21): pickle opcode walk (protocol 0–5, raw, legacy torch, PyTorch zip/TorchScript, `.mar`, `.npz`, `.npy` object arrays, joblib plain/zlib/gzip/bz2/xz) against a deny/allow list; safetensors, GGUF (chat-template SSTI), ONNX (custom op domains, external-data paths), Keras v3 / HDF5 (`Lambda`, dangerous callables), TFLite/`.pte` inventory; zip-slip and malformed containers; caps on opcodes, decompression and memory — never unpickled | `modelfiles.py`, `data/ait/model-rules.json` | working — verified on hand-built samples only (see limits) |
| Model / dataset licence verdicts (C25) against `use_context`, base-model inheritance, allow/deny | `licences.py`, `data/ait/licence-verdicts.json` | working (advisory, not legal advice) |
| MCP configs (C26/C29/C31): Claude Desktop/Code, Cursor, VS Code (JSONC), Codex TOML, Windsurf, Gemini; dangerous commands, poisoned descriptions, literal secrets, scope, plain-http — nothing launched (G8) | `mcp.py`, `data/ait/command-rules.json` (57), `data/ait/poison-patterns.json` (8) | working |
| Agent skills / plugins (C30/C31) | `skills.py` | working |
| AI secrets (C32), redacted, digest-keyed | `secrets.py` | working |
| CycloneDX 1.7 emission (C05), 1.6 compatible, findings as `vulnerabilities[]` | `bom.py`, `--emit-bom`, `bom` command | working |
| Reports: table, JSON, SARIF 2.1.0, self-contained HTML | `report.py`, `html_report.py` | working |
| Policy (C33): `fail_on`, `use_context`, path ignores, package allow/deny with ranges, licence allow/deny, lint | `policy.py`, `policy lint` | working |
| Suppressions (C34) with mandatory expiry; `.snyk` import. A known-malicious finding (verdict `malicious`) is accepted only by an expiring suppression naming its fingerprint — never by `ignore`, `allow_packages`, a rule/path/advisory-wide suppression or a baseline | `policy.py`, `--snyk` | working |
| Baseline (C35) | `--write-baseline`, `--baseline` | working |
| Coverage honesty: a skipped manifest, agent config, skill script or model-file part is a medium `ait.*.not-analysable` finding where the file is; oversized text files skipped by the secrets pass and the 200,000-file walk cap are notes; an unreachable source (OSV) exits 2 | `model.not_analysable`, `scanner.py` | working |
| Local MCP server exposing `scan_ai_supply_chain` (C44), protocol 2025-06-18 | `mcpserver.py`, `mcp serve` | working |
| GitHub Action, pre-commit hook, CI matrix + wheel job | `action/`, `.pre-commit-hooks.yaml`, `.github/workflows/ci.yml` | written — **not yet run on GitHub** |
| Golden fixture suite: 14 fixtures; F02/F04b/F12 are false-positive canaries | `tests/test_golden.py` | working |

## Not built yet (next slices)

| Slice | Plan item | Blocker / note |
|---|---|---|
| Scheduled definition refresh (MAL + KEV) | C14/C20 data ops | The bundled data is a point-in-time build; nothing refreshes it yet (see "Definition data" below) |
| Signed definition bundles (verify, install, rollback) | C50, `defs/` | Needs the AIT root signing key and a maintained minisign implementation (14a §7.3) |
| SecDB API v1 client (signed-in path, MCP assessments) | §4.8, Appendix I/K | Needs the contract client in `secdb/` and an API key |
| BYO-key third-party providers (e.g. VirusTotal) | §6.4 | `providers/` adapter not started |
| MCP reputation consumption + tool-list poisoning layer | C24/C26/C28 | Depends on the SecDB client |
| `tools/build_command_rules.py` (rule generator / self-test in repo) | Appendix H | Rules are self-tested by `tests/test_mcp.py`; the generator is not in the repo |
| Cloud service `aibom-cloud` (FastAPI + PostgreSQL `app.aibom_*`) | Appendix J | Separate closed repo; needs the database host |

## Definition data

| Asset | Content | Input (provenance) | Size |
|---|---|---|---|
| `data/ait/malicious-versions.json.gz` (schema `ait-malicious-versions/2`) | 235,476 active `MAL-` records over 235,475 packages; 214,803 mark every version (mostly typosquat / dependency-confusion packages), the rest list 65,651 exact versions; 363 withdrawn records (PyPI 25, npm 338) kept in a separate `withdrawn` section | OSV bulk exports `PyPI/all.zip` (37.9 MB) and `npm/all.zip` (221 MB), 2026-11-14 — SHA-256 of each input is recorded in the file and shown by `defs status` | 3.06 MB (gzip of compact JSON) |
| `data/ait/kev.json` | 1,781 CVEs | CISA KEV catalog 2026.11.13 (CC0) | 0.3 MB |

Quality checks on this build:

- no withdrawn record is active; `fastapi 0.136.3` (the withdrawn record that the earlier v0.2.0
  snapshot shipped as CRITICAL) is reported as `withdrawn` (info, exit 0, a SARIF suppression);
- popular packages carry exact-version records only — compromised releases such as axios
  0.30.4/1.14.1, chalk 5.6.1, debug 4.4.2, nx, litellm 1.82.7/1.82.8/1.107.0, lightning
  2.6.2/2.6.3, mistralai 2.4.6, @mastra/core 1.42.1 — never "every version"; a unit test pins this;
- two real npm lockfiles (877 packages) scanned offline: zero malicious findings, 1.7 s each;
- snapshot load ≈ 0.75 s (records are materialised lazily per looked-up package).

Refresh:

```bash
curl -fLo PyPI-all.zip https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
curl -fLo npm-all.zip  https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
python tools/build_malicious.py --zip PyPI-all.zip --zip npm-all.zip --replace
python tools/build_kev.py --url
```

Each refresh adds ~3 MB of binary to git history; once signed bundles (C50) exist, the wheel should
ship a smaller seed and the full set should arrive as a verified bundle.

## Test coverage

255 unit and golden tests (`python -m unittest discover -s tests`), about 1.7 s. The wheel is built
offline and installed into a clean virtual environment to check that the bundled data ships.

## Known limits (measure before GA)

- **Model files:** no real checkpoints were scanned yet (torch/numpy/joblib/Keras/ONNX are not
  installed in the dev env), so real-world false-positive rates are unknown; every model rule has
  `fp_rate_measured: null`. `lz4` joblib and the old torch tar format are reported as not analysed.
  HDF5 detection reads the first 32 MiB and last 8 MiB. GGUF chat-template checks are patterns and
  can be evaded by heavy obfuscation.
- **Secrets:** placeholder filtering drops values containing words such as `example` or `123456`.
- **MCP / skills:** `supply.npx-unpinned` covers `npx` only (not `bunx` / `pnpm dlx`); token-length
  bounds for HF/GitHub tokens are tight; `prod.env`-style names are not treated as `.env` files by
  the command rules.
- **Licences:** verdicts are advisory, not legal advice.

## Deviations kept from Appendix H.4

- CLI name `aiterprise-scan`; `src/aiterprise_scan/` layout; `scan` takes a positional target.
- MCP rules run on config text only; live tool lists are never fetched.
- KEV instead of EPSS for exploitation priority.

## Reproduce

```bash
python -m venv .venv && .venv/bin/pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -p "test_*.py"
PYTHONPATH=src python -m aiterprise_scan scan tests/golden/F01-malicious-requirements --offline
PYTHONPATH=src python -m aiterprise_scan scan . --offline --exclude "tests/**" --fail-on high   # self-scan
```
