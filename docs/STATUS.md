# Implementation status — `aiterprise-scan` 0.1.0 (rewrite)

Updated 2026-11-17. Design of record: `aiterprise-doc/13-APP-AIBOM.md` (AI2). This is a clean-room
rewrite of the OSS engine; the v0.2.0 code described in that document's Appendix H was not available,
so this table restates Appendix H.1 against what exists in this repository today.

## Built

| Capability (plan item) | Module / command | Status |
|---|---|---|
| One-command scan of a repo, file, archive, BOM or agent config | `aiterprise-scan scan [<path>]`, bare `aiterprise-scan <path>` | working |
| Repository discovery (W2): requirements, pyproject (PEP 621 + Poetry), Pipfile(.lock), poetry.lock, uv.lock, environment.yml, package.json, package-lock v1–v3, pnpm-lock v5/v6/v9, yarn.lock v1/berry; Python/JS imports and notebooks. Lockfile wins over manifest; a range is never an exact version | `discover.py` | working |
| Component taxonomy (§4.2) | `data/ait/taxonomy.json`, `taxonomy.py` | working for libraries (a first-party, curated list of PyPI and npm names). Model files, model and dataset references, MCP servers and configs, and agent skills are component types too; `ai-endpoint` is declared but nothing produces it, and prompts and vector stores are not component types (C02) |
| BOM ingest (C09): CycloneDX 1.4–1.7 (nested), SPDX 2.x JSON, UTF-8/UTF-16 with or without BOM; versionless components marked unjudgeable | `ingest.py` | working |
| Known-malicious versions (C14): OSV `MAL-` snapshot; exact, all-versions, range-admits-malicious, unpinned. Withdrawn records reported as `withdrawn`, never active, never dropped (§4.3) | `intel_malicious.py`, `data/ait/malicious-versions.json.gz` | working — 235,492 records (npm 223,463 · PyPI 12,029) + 363 withdrawn, built 2026-11-16 |
| Slopsquatting and registry checks: names that do not exist on PyPI/npm, packages under 72 h old, pinned versions that do not exist, npm security holders; lookalike names of popular and AI packages (offline) | `registry.py`, `data/ait/popular-packages.json` | working |
| Vulnerabilities (C19): OSV querybatch → per-advisory details, cached, alias de-duplication, CVSS v3 base score, fix-version advice | `vulns.py`, `net.py`, `cache.py` | working (verified live against api.osv.dev) |
| Offline advisory subset: OSV advisories for the 164 AI-taxonomy packages, used offline and when OSV is unreachable | `data/ait/vuln-subset.json.gz` | working — 2,921 advisories over 65 packages, built 2026-11-16 |
| Exploitation priority (C20): CISA KEV upgrades to critical | `vulns.py`, `data/ait/kev.json` | working — 1,781 CVEs, catalog 2026.11.13 |
| Model files (C21): pickle opcode walk (protocol 0–5, raw, legacy torch, PyTorch zip/TorchScript, `.mar`, `.npz`, `.npy`, joblib), safetensors, GGUF chat-template SSTI, ONNX custom ops / external data, Keras v3 / HDF5 `Lambda`, TFLite/`.pte` inventory; zip-slip; caps — never unpickled | `modelfiles.py`, `data/ait/model-rules.json` | working — verified on hand-built samples only (see limits) |
| Package archives: wheels, sdists, tarballs, eggs, MCPB/DXT bundles — `.pth` payloads, `setup.py` / npm lifecycle commands, path traversal, model members | `archives.py`, `mcpb.py` | working |
| Model / dataset licence verdicts (C25) against `use_context`, base-model inheritance, allow/deny | `licences.py`, `data/ait/licence-verdicts.json` | working (advisory, not legal advice) |
| MCP configs (C26/C29/C31): Claude Desktop/Code, Cursor, VS Code (JSONC), Codex TOML, Windsurf, Gemini; dangerous commands, poisoned descriptions, literal secrets, scope, plain-http — nothing launched (G8) | `mcp.py`; the rule sets, shared with skills, MCP bundles and package archives, in `textrules.py` with `data/ait/command-rules.json` (57), `data/ait/poison-patterns.json` (8) | working — one rule makes the same finding wherever its text was found |
| Agent skills / plugins (C30/C31) | `skills.py` | working |
| AI secrets (C32), redacted, digest-keyed | `secrets.py` | working |
| SecDB API v1 client (§4.8, Appendix I/K): `/v1/me` limits, lookups (single, batch on paid plans), MCP URL prefixes and assessments, file verdicts, data notices, FP reports with consent, report upload; budget from the plan; 429 → UNVERIFIED, never clean | `secdb.py`, `account.py`, `login` / `logout` / `status` / `report-fp` / `upload` | working — verified live with a free key (`/v1/me`, `/v1/usage`, lookups within the 4/min budget); batch and upload are plan-gated and not live-tested; `login --install` (anonymous install token) is tested against a stand-in only, never run against the live service; the named-MCP assessment call is in the client but is never made, because no analyzer sets a server's registry name (H.5 #1) |
| BYO-key third-party enrichment (C38, §6.4, K.8): `scan --byo virustotal=ENV_VAR` looks up the SHA-256 of the model files and package archives of a scan directly at VirusTotal with the customer's own key. FD22 guards: hash lookups only (no upload path), no cache, findings under `ext.virustotal.*` with a null FP rate and never our `malicious` verdict, left out of everything sent to SecDB or a cloud, redirects refused, the key in no output; quota, refused key, outage, budget and `--offline` are reported as not verified, never clean | `providers/`, `docs/providers.md` | working against a local stand-in (72 tests) — **no live VirusTotal call was made** (no key), so the response shape is from the public API documentation only |
| Signed definition bundles (C50): minisign (pure-Python Ed25519, RFC 8032) over the manifest, root-signed `signing-keys.json` with rollback and expiry checks, `release_id` from JCS, archive hash before unpack, atomic install, rollback, per-load re-check | `ed25519.py`, `minisign.py`, `bundles.py`, `defscli.py`, `defs verify/install/update/rollback`, `tools/build_bundle.py` | working — a locally built bundle verified, installed and used; interop with the reference `minisign` passes both ways in CI. Only `.tar.gz` bundles were exercised: a `.tar.zst` bundle (the design's format, §5.4) needs Python 3.14+, and the image, the binaries and the Action run 3.12 |
| Rule quality: per-finding `fp_rate_measured` (measured, or null) and `examined` coverage counts | `quality.py`, `data/ait/rule-quality.json`, `tools/measure_fp.py` | working — `ait.secret.*` measured (3.41 % over 205 clean projects) and `ait.skill.*` measured (11.64 % of 275 installed agent skills trip a skill rule; per-rule rates are in the file); MCP, model-file and archive rules are `null` |
| CycloneDX 1.7 emission (C05), 1.6 compatible, findings as `vulnerabilities[]` | `bom.py`, `--emit-bom`, `bom` command | working |
| Reports: table, JSON, SARIF 2.1.0, self-contained HTML; data notices | `report.py`, `reportdoc.py`, `html_report.py` | working — the JSON report is the report document: one module (`reportdoc.py`) owns its layout, its `schema` (`aiterprise-report/1`) and the upload view (no third-party provider results, no local paths), which the SecDB client applies to everything it sends |
| Policy (C33), suppressions with mandatory expiry (C34), `.snyk` import, baseline (C35); malicious findings accepted only by an expiring fingerprint suppression; UI suppressions in `.aiterprise/suppressions.json` | `policy.py`, `gate.py` | working — one gated scan (`gate.py`) decides pass or failure for the CLI, the UI and the MCP tool: the policy, the project's suppressions and the baseline are read from the scanned project's directory, also for a single-file target |
| Org policy sync and cloud upload: `policy pull` (ETag, refuses a policy this scanner cannot load), `scan --upload --cloud`, `upload --cloud`; keys only over https (http to loopback only), and a request that carries a key never follows a redirect | `cloudpolicy.py`, `account.py` | working — verified end to end against a local `aibom-cloud` with a real SecDB key (upload 201, pull 200 then 304) |
| Coverage honesty: skipped files are `ait.*.not-analysable` findings; an unreachable source exits 2 | `model.not_analysable`, `scanner.py`, `sources.py` | working — every source is named once in `sources.py`, with the rule families it raises, and counts its own coverage; every judgement, the licence and deny-list ones included, is counted as a source; a test scans all golden fixtures and fails if a finding reports data from zero consulted sources |
| Local web UI: scan history, findings with filters, inventory, coverage, diff between scans, suppress, SecDB account, defs update; 127.0.0.1 only, token → HttpOnly cookie, Host check, CSRF + Origin, CSP nonce | `ui.py`, `history.py`, `ui`, `scan --save` | working — checked in a real browser, including a 375 px viewport |
| Local MCP server exposing `scan_ai_supply_chain` (C44), protocol 2025-06-18; registry manifest | `mcpserver.py`, `mcp serve`, `server.json` | working; `server.json` fits the registry schema (2025-12-11); not published to the MCP registry, which needs the PyPI release first. The tool goes through the same gate as the CLI and the UI; it never consults SecDB, and its coverage says so |
| Acceptance demo: five planted problems, one scan, offline and online; `--exe` holds a built binary to the same five | `tools/killer_demo.py` | working — 5/5 from source offline and online in CI (the online run fails unless the report shows OSV and the registries answered; without a network it would still find all five from bundled data, so the check is what makes it an online test), and from the six binaries in CI (Linux, macOS and Windows, each x86-64 and arm64) |
| Packaging: wheel + sdist, single-file binaries (PyInstaller), container image, Sigstore-signed release, self-SBOM, PyPI trusted publishing | `packaging/`, `Dockerfile`, `.github/workflows/release.yml`, `binaries.yml` | wheel, sdist, self-SBOM and container image built and checked in CI; CI builds the six binaries (Linux, macOS and Windows, each x86-64 and arm64, natively on its own runner) with the release's own `binaries.yml` and each passes the killer demo (5/5, exit 1); the tag-triggered release (signing, PyPI, ghcr.io) **not yet run** — `RELEASING.md` lists the one-time setup it needs (a PyPI trusted publisher; the name is free) |
| CI: test matrix, wheel and sdist, self-scan, killer demo, licence check, minisign interop, docs, container, binaries, the GitHub Action, the pre-commit hook | `.github/workflows/ci.yml` | working — green on `main` |
| Scheduled definition refresh (MAL + KEV + advisory subset) | `.github/workflows/refresh-defs.yml` | working — weekly. The first scheduled run (2026-11-16) rebuilt the data, passed the full tests and the killer demo on it, and opened the refresh pull request itself (the repository lets Actions create pull requests); it was merged the same day. CI on such a pull request starts only when it is closed and reopened |
| Documentation site (MkDocs, strict build); generated rules reference | `mkdocs.yml`, `docs/`, `tools/gen_rules_doc.py` | working — builds locally with `--strict` |
| GitHub Action (with optional `api-key`), pre-commit hook | `action/`, `.pre-commit-hooks.yaml` | working — CI uses the action on the killer-demo repository (the gate fails, `exit-code` 1, report, SARIF and AI-BOM written) and on a clean fixture (`exit-code` 0), and `pre-commit try-repo` runs the hook on both. Not exercised: the SARIF upload to code scanning (not available to a private repository) and the `api-key` input |
| Golden fixture suite: 14 fixtures; F02/F04b/F12 are false-positive canaries | `tests/test_golden.py` | working |
| Cloud service `aibom-cloud` (FastAPI + PostgreSQL; Appendix J): upload, scan history, finding state, deltas, inventory, watches and webhooks, org policy, baselines, staff console | separate private repository `jtopaz1/aibom-cloud` | built, **not deployed** — no host has been named. 100 tests; its CI runs them on SQLite and on PostgreSQL 17 (a database per test, built from the migration), and a docker job builds the image, starts it with PostgreSQL, uploads a report with the CLI and reads it back. It departs from Appendix J: sign-in is a pasted API key (no Console session, so no users or seats), scans are processed by an in-process background task (no queue worker), and it has its own ingest endpoint and tables. Not built: rate limiting (`429` + `Retry-After`), SARIF export, FP forwarding to SecDB, `POST /cli/link`, metrics. Both plan gates default to `community`; production sets `pro` and `team` |

## Not built yet

| Slice | Plan item | Blocker / note |
|---|---|---|
| Pinned AIT root key | C50 / O-23 | Not published by SecDB; `--root-key` or `AITERPRISE_ROOT_KEY` is required until it is |
| Published AIT bundles | C50 data ops | `GET /v1/releases/latest?domain=AIT&format=ait-bundle` returns 404 today; `defs update` says so and keeps the current data |
| False-positive rates for MCP, model-file and archive rules | §4.3 | Needs corpora: the machine used for the skill and secret measurements has 15 MCP configs and one package with model files, under the 25-sample minimum |
| More BYO-key providers (urlscan.io, Web Risk) | §6.4 | VirusTotal is the only adapter; URL reputation for MCP endpoints is v2 in the design |
| Live MCP tool-list poisoning layer | C24/C28 | Deliberately not done: the scanner never launches servers (G8); descriptions in configs are judged |
| `tools/build_command_rules.py` (rule generator) | Appendix H | Rules are self-tested by `tests/test_textrules.py`; the generator is not in the repo |

## Not built: the design audit of 2026-11-16

An audit by reading compared this repository and `aibom-cloud` with the design's first-release scope
(the MVP and the launch gate of §10.6; for the cloud, step 1 of J.6). It listed 72 requirements: 30
built, 21 partly built, 12 not built, 7 blocked on parties outside the repositories, and 2 it could
not confirm. The rows below are the scanner's requirements that are not fully built and are not
already listed above; the cloud's are in its row under *Built*.

| Slice | Plan item | State |
|---|---|---|
| Prompts, vector stores and AI endpoints as component classes | C02 | not built |
| OpenClaw / DSH configs; skills folders of the machine | §4.1 | not built — `mcp --agent-configs` reads the machine's MCP configs only; skills are read inside a scanned directory |
| Keyboard-walk similarity; ownership-transfer and single-maintainer signals; crates.io | C16 / C17 | not built — lookalike names use edit distance; registry checks are existence and age |
| A bundled list of model hashes seen in incidents | C23 | not built — model hashes are checked at SecDB only, when logged in |
| 20 poison patterns | S2 | 8 patterns |
| Named-MCP assessments used by `scan`; a static tool-list parser | H.5 #1 / K.3 / C26 | the client call exists and is never made; the parser is not built |
| SkillSpector integration | G3 / C30 | not built — the skill analyzer has its own 0–100 risk score |
| Opt-in telemetry (rule ids and counts) | §4.8 | not built — there is no telemetry code at all |
| `--defs-version` pin | §5.4 | not built |
| Pull-request comments from the Action | C42 | not built — the Action uploads SARIF and gates |
| Editor task templates; GitLab CI template | C45 / S3 | not built |
| False-positive corpus of at least 200 AI repositories and 500 real model files; automatic demotion of a noisy rule | §5.5 | not built — the corpora are local site-packages projects and installed skills; a critical rule with a measured FP rate above zero still reports critical |
| Cold scan of a 10,000-file monorepo under 60 s | §5.5 | not measured — there is no benchmark |
| FP methodology page, `security.txt`, function-parity matrix, DCO | §10.6 #7 / §8.4 / W1 | not built |
| Package licences (manifest and deps.dev) | §5.3 | not built — licence verdicts cover models and datasets |
| Per-record licence check of the redistributed OSV records | H.3 | not built — the builder writes a note; nothing checks a record's terms |
| Device-code login | J.3 | blocked on the platform Console — login is a pasted key or an install token |
| `watch` command | S6 | not built |

## Definition data

| Asset | Content | Input (provenance) | Size |
|---|---|---|---|
| `malicious-versions.json.gz` (schema `ait-malicious-versions/2`) | 235,492 active `MAL-` records over 235,491 packages; 214,803 mark every version, the rest list 65,677 exact versions; 363 withdrawn records kept apart | OSV bulk exports `PyPI/all.zip` and `npm/all.zip`, 2026-11-16 — SHA-256 of each input recorded in the file and shown by `defs status` | 3.06 MB |
| `vuln-subset.json.gz` (schema `ait-vuln-subset/1`) | 2,921 advisories for 65 of the 164 AI-taxonomy packages | Same OSV exports; per-record licences (GHSA, PYSEC: CC-BY 4.0) | 0.24 MB |
| `kev.json` | 1,781 CVEs | CISA KEV catalog 2026.11.13 (CC0) | 0.3 MB |
| `rule-quality.json` | measured FP rates | `tools/measure_fp.py` over 210 local site-packages projects (secrets) and 275 installed agent skills (skills) | 5 KB |

The counts above are the 2026-11-16 build, made by the first scheduled refresh (16 more `MAL-`
records than the 2026-11-14 build it replaced). Every weekly refresh changes them;
`aiterprise-scan defs status` prints what a given build carries.

Quality checks on the malicious snapshot: no withdrawn record is active (`fastapi 0.136.3` is
reported as `withdrawn`, exit 0); popular packages carry exact-version records only (axios
0.30.4/1.14.1, chalk 5.6.1, debug 4.4.2, litellm 1.82.7/1.82.8/1.107.0, …), pinned by a unit test;
two real npm lockfiles (877 packages) scanned offline with zero malicious findings (that scan was
made on the 2026-11-14 build).

Refresh by hand (the `refresh-defs` workflow runs the same steps every Monday and proposes the result as a pull request):

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
- **Skill rules are noisy on real skills.** Of 275 installed, in-use skills, 32 trip a skill rule
  (before the fixes below: 55 of 325 skill copies). `desc.hidden.conceal` and
  `desc.secret.read-exfil` are critical and still fire on 4.0 % and 1.8 %: the description-poisoning
  patterns were written for short tool descriptions and also run over long skill bodies, where
  "never tell a user the report was scheduled when it was not" is ordinary guidance. The measurement
  found four plain faults, now fixed with tests: `read` matched inside "ready", "don't let … them"
  counted as concealment, `host` matched PowerShell's `Write-Host`, and a negated verb ("never copy
  secrets") counted as the instruction it forbids. The body/description split is not done. Treat
  skill-body findings as leads.
- **Licences:** verdicts are advisory, not legal advice.
- **KEV severity (decided 2026-11-14):** a CVE listed in CISA KEV is upgraded to **critical**
  (`ait.vuln.kev`), whatever the advisory's own CVSS severity — known exploitation outranks the
  base score.

## Deviations kept from Appendix H.4

- CLI name `aiterprise-scan`; `src/aiterprise_scan/` layout; `scan` takes a positional target.
- MCP rules run on config text only; live tool lists are never fetched.
- KEV instead of EPSS for exploitation priority.
- Standard library only: the design lists third-party packages (typer, picklescan,
  cyclonedx-python-lib and others); none is used.
- Python 3.11+ (the design says 3.12+); the GitHub Action is a composite action; the version is
  0.1.0, not CalVer.

## Reproduce

```bash
python -m venv .venv && .venv/bin/pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -p "test_*.py"
python tools/killer_demo.py
PYTHONPATH=src python -m aiterprise_scan scan . --offline --exclude "tests/**" --fail-on high   # self-scan
pip install -r docs/requirements.txt && mkdocs build --strict
```
