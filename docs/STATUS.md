# Implementation status — `aiterprise-scan` 0.1.0 (rewrite)

Updated 2026-11-14. Design of record: `aiterprise-doc/13-APP-AIBOM.md` (AI2). This is a clean-room
rewrite of the OSS engine; the v0.2.0 code described in that document's Appendix H was not available,
so this table restates Appendix H.1 against what exists in this repository today.

## Built

| Capability (plan item) | Module / command | Status |
|---|---|---|
| One-command scan of a repo, file, archive, BOM or agent config | `aiterprise-scan scan [<path>]`, bare `aiterprise-scan <path>` | working |
| Repository discovery (W2): requirements, pyproject (PEP 621 + Poetry), Pipfile(.lock), poetry.lock, uv.lock, environment.yml, package.json, package-lock v1–v3, pnpm-lock v5/v6/v9, yarn.lock v1/berry; Python/JS imports and notebooks. Lockfile wins over manifest; a range is never an exact version | `discover.py` | working |
| Component taxonomy (§4.2) | `data/ait/taxonomy.json`, `taxonomy.py` | working (first-party, curated) |
| BOM ingest (C09): CycloneDX 1.4–1.7 (nested), SPDX 2.x JSON, UTF-8/UTF-16 with or without BOM; versionless components marked unjudgeable | `ingest.py` | working |
| Known-malicious versions (C14): OSV `MAL-` snapshot; exact, all-versions, range-admits-malicious, unpinned. Withdrawn records reported as `withdrawn`, never active, never dropped (§4.3) | `intel_malicious.py`, `data/ait/malicious-versions.json.gz` | working — 235,476 records (npm 223,456 · PyPI 12,020) + 363 withdrawn, built 2026-11-14 |
| Slopsquatting and registry checks: names that do not exist on PyPI/npm, packages under 72 h old, pinned versions that do not exist, npm security holders; lookalike names of popular and AI packages (offline) | `registry.py`, `data/ait/popular-packages.json` | working |
| Vulnerabilities (C19): OSV querybatch → per-advisory details, cached, alias de-duplication, CVSS v3 base score, fix-version advice | `vulns.py`, `net.py`, `cache.py` | working (verified live against api.osv.dev) |
| Offline advisory subset: OSV advisories for the 164 AI-taxonomy packages, used offline and when OSV is unreachable | `data/ait/vuln-subset.json.gz` | working — 2,921 advisories over 65 packages, built 2026-11-14 |
| Exploitation priority (C20): CISA KEV upgrades to critical | `vulns.py`, `data/ait/kev.json` | working — 1,781 CVEs, catalog 2026.11.13 |
| Model files (C21): pickle opcode walk (protocol 0–5, raw, legacy torch, PyTorch zip/TorchScript, `.mar`, `.npz`, `.npy`, joblib), safetensors, GGUF chat-template SSTI, ONNX custom ops / external data, Keras v3 / HDF5 `Lambda`, TFLite/`.pte` inventory; zip-slip; caps — never unpickled | `modelfiles.py`, `data/ait/model-rules.json` | working — verified on hand-built samples only (see limits) |
| Package archives: wheels, sdists, tarballs, eggs, MCPB/DXT bundles — `.pth` payloads, `setup.py` / npm lifecycle commands, path traversal, model members | `archives.py`, `mcpb.py` | working |
| Model / dataset licence verdicts (C25) against `use_context`, base-model inheritance, allow/deny | `licences.py`, `data/ait/licence-verdicts.json` | working (advisory, not legal advice) |
| MCP configs (C26/C29/C31): Claude Desktop/Code, Cursor, VS Code (JSONC), Codex TOML, Windsurf, Gemini; dangerous commands, poisoned descriptions, literal secrets, scope, plain-http — nothing launched (G8) | `mcp.py`, `data/ait/command-rules.json` (57), `data/ait/poison-patterns.json` (8) | working |
| Agent skills / plugins (C30/C31) | `skills.py` | working |
| AI secrets (C32), redacted, digest-keyed | `secrets.py` | working |
| SecDB API v1 client (§4.8, Appendix I/K): `/v1/me` limits, lookups (single, batch on paid plans), MCP URL prefixes and assessments, file verdicts, data notices, FP reports with consent, report upload; budget from the plan; 429 → UNVERIFIED, never clean | `secdb.py`, `account.py`, `login` / `logout` / `status` / `report-fp` / `upload` | working — verified live with a free key (`/v1/me`, `/v1/usage`, lookups within the 4/min budget); batch and upload are plan-gated and not live-tested |
| Signed definition bundles (C50): minisign (pure-Python Ed25519, RFC 8032) over the manifest, root-signed `signing-keys.json` with rollback and expiry checks, `release_id` from JCS, archive hash before unpack, atomic install, rollback, per-load re-check | `ed25519.py`, `minisign.py`, `bundles.py`, `defscli.py`, `defs verify/install/update/rollback`, `tools/build_bundle.py` | working — a locally built bundle verified, installed and used; interop with the reference `minisign` passes both ways in CI |
| Rule quality: per-finding `fp_rate_measured` (measured, or null) and `examined` coverage counts | `quality.py`, `data/ait/rule-quality.json`, `tools/measure_fp.py` | working — `ait.secret.*` measured (3.41 % over 205 clean projects); every other rule is `null` |
| CycloneDX 1.7 emission (C05), 1.6 compatible, findings as `vulnerabilities[]` | `bom.py`, `--emit-bom`, `bom` command | working |
| Reports: table, JSON, SARIF 2.1.0, self-contained HTML; data notices | `report.py`, `html_report.py` | working |
| Policy (C33), suppressions with mandatory expiry (C34), `.snyk` import, baseline (C35); malicious findings accepted only by an expiring fingerprint suppression; UI suppressions in `.aiterprise/suppressions.json` | `policy.py` | working |
| Org policy sync and cloud upload: `policy pull` (ETag, refuses a policy this scanner cannot load), `scan --upload --cloud`, `upload --cloud`; keys only over https (http to loopback only) | `cloudpolicy.py`, `account.py` | working — verified end to end against a local `aibom-cloud` with a real SecDB key (upload 201, pull 200 then 304) |
| Coverage honesty: skipped files are `ait.*.not-analysable` findings; an unreachable source exits 2 | `model.not_analysable`, `scanner.py` | working |
| Local web UI: scan history, findings with filters, inventory, coverage, diff between scans, suppress, SecDB account, defs update; 127.0.0.1 only, token → HttpOnly cookie, Host check, CSRF + Origin, CSP nonce | `ui.py`, `history.py`, `ui`, `scan --save` | working — checked in a real browser, including a 375 px viewport |
| Local MCP server exposing `scan_ai_supply_chain` (C44), protocol 2025-06-18; registry manifest | `mcpserver.py`, `mcp serve`, `server.json` | working; not published to the MCP registry |
| Acceptance demo: five planted problems, one offline scan; `--exe` holds a built binary to the same five | `tools/killer_demo.py` | working — 5/5 from source, and from the Linux x86-64, macOS arm64 and Windows x86-64 binaries in CI |
| Packaging: wheel + sdist, single-file binaries (PyInstaller), container image, Sigstore-signed release, self-SBOM, PyPI trusted publishing | `packaging/`, `Dockerfile`, `.github/workflows/release.yml`, `binaries.yml` | wheel and container image built and checked in CI; CI builds the Linux, macOS and Windows binaries with the release's own `binaries.yml` and each passes the killer demo (5/5, exit 1); the tag-triggered release (signing, PyPI, ghcr.io) **not yet run** |
| CI: test matrix, wheel, self-scan, killer demo, licence check, minisign interop, docs, container, binaries | `.github/workflows/ci.yml` | working — green on GitHub (PR #2) |
| Scheduled definition refresh (MAL + KEV + advisory subset) | `.github/workflows/refresh-defs.yml` | written — weekly; rebuilds the data, runs the full tests and the killer demo on it, then proposes it on `defs/refresh`. Runs only from the default branch, so **not yet run**; opening the pull request needs the repository setting that lets Actions create pull requests (off today), otherwise the run links to the compare page |
| Documentation site (MkDocs, strict build); generated rules reference | `mkdocs.yml`, `docs/`, `tools/gen_rules_doc.py` | working — builds locally with `--strict` |
| GitHub Action (with optional `api-key`), pre-commit hook | `action/`, `.pre-commit-hooks.yaml` | written — not yet run on GitHub |
| Golden fixture suite: 14 fixtures; F02/F04b/F12 are false-positive canaries | `tests/test_golden.py` | working |

## Not built yet

| Slice | Plan item | Blocker / note |
|---|---|---|
| Pinned AIT root key | C50 / O-23 | Not published by SecDB; `--root-key` or `AITERPRISE_ROOT_KEY` is required until it is |
| Published AIT bundles | C50 data ops | `GET /v1/releases/latest?domain=AIT&format=ait-bundle` returns 404 today; `defs update` says so and keeps the current data |
| False-positive rates for the other rule families | §4.3 | Needs labelled corpora with model files, MCP configs and skills; the site-packages corpus only exercises secrets |
| BYO-key third-party providers (e.g. VirusTotal) | §6.4 | `providers/` adapter not started |
| Live MCP tool-list poisoning layer | C24/C28 | Deliberately not done: the scanner never launches servers (G8); descriptions in configs are judged |
| `tools/build_command_rules.py` (rule generator) | Appendix H | Rules are self-tested by `tests/test_mcp.py`; the generator is not in the repo |
| Cloud service `aibom-cloud` (FastAPI + PostgreSQL) | Appendix J | Separate repository (`C:\Project\aibom-cloud`), 92 tests; dashboard checked in a browser on SQLite; not run on PostgreSQL or Docker, not deployed, no remote |

## Definition data

| Asset | Content | Input (provenance) | Size |
|---|---|---|---|
| `malicious-versions.json.gz` (schema `ait-malicious-versions/2`) | 235,476 active `MAL-` records over 235,475 packages; 214,803 mark every version, the rest list 65,651 exact versions; 363 withdrawn records kept apart | OSV bulk exports `PyPI/all.zip` and `npm/all.zip`, 2026-11-14 — SHA-256 of each input recorded in the file and shown by `defs status` | 3.06 MB |
| `vuln-subset.json.gz` (schema `ait-vuln-subset/1`) | 2,921 advisories for 65 of the 164 AI-taxonomy packages | Same OSV exports; per-record licences (GHSA, PYSEC: CC-BY 4.0) | 0.24 MB |
| `kev.json` | 1,781 CVEs | CISA KEV catalog 2026.11.13 (CC0) | 0.3 MB |
| `rule-quality.json` | measured FP rates | `tools/measure_fp.py` over 210 local site-packages projects | 2 KB |

Quality checks on the malicious snapshot: no withdrawn record is active (`fastapi 0.136.3` is
reported as `withdrawn`, exit 0); popular packages carry exact-version records only (axios
0.30.4/1.14.1, chalk 5.6.1, debug 4.4.2, litellm 1.82.7/1.82.8/1.107.0, …), pinned by a unit test;
two real npm lockfiles (877 packages) scanned offline with zero malicious findings.

Refresh by hand (the `refresh-defs` workflow runs the same steps weekly once it is on the default branch):

```bash
curl -fLo PyPI-all.zip https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
curl -fLo npm-all.zip  https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
python tools/build_malicious.py --zip PyPI-all.zip --zip npm-all.zip --replace
python tools/build_vuln_subset.py --zip PyPI-all.zip --zip npm-all.zip
python tools/build_kev.py --url
python tools/gen_rules_doc.py
```

## Known limits (measure before GA)

- **Model files:** no real checkpoints were scanned yet, so real-world false-positive rates are
  unknown; every model rule has `fp_rate_measured: null`. `lz4` joblib and the old torch tar format
  are reported as not analysed. GGUF chat-template checks are patterns and can be evaded.
- **Secrets:** all 7 flagged projects behind the measured 3.41 % were flagged by the PEM
  private-key rule; placeholder filtering drops values containing words such as `example`.
- **MCP / skills:** `supply.npx-unpinned` covers `npx` only (not `bunx` / `pnpm dlx`).
- **Licences:** verdicts are advisory, not legal advice.
- **KEV severity (decided 2026-11-14):** a CVE listed in CISA KEV is upgraded to **critical**
  (`ait.vuln.kev`), whatever the advisory's own CVSS severity — known exploitation outranks the
  base score.

## Deviations kept from Appendix H.4

- CLI name `aiterprise-scan`; `src/aiterprise_scan/` layout; `scan` takes a positional target.
- MCP rules run on config text only; live tool lists are never fetched.
- KEV instead of EPSS for exploitation priority.

## Reproduce

```bash
python -m venv .venv && .venv/bin/pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -p "test_*.py"
python tools/killer_demo.py
PYTHONPATH=src python -m aiterprise_scan scan . --offline --exclude "tests/**" --fail-on high   # self-scan
pip install -r docs/requirements.txt && mkdocs build --strict
```
