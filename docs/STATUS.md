# Implementation status — `aiterprise-scan` 0.1.0 (rewrite)

Updated 2026-11-17. Design of record: `aiterprise-doc/13-APP-AIBOM.md` (AI2). This is a clean-room
rewrite of the OSS engine; the v0.2.0 code described in that document's Appendix H was not available,
so this table restates Appendix H.1 against what exists in this repository today.

## Built

| Capability (plan item) | Module / command | Status |
|---|---|---|
| One-command scan of a repo, file, archive, BOM or agent config | `aiterprise-scan scan [<path>]`, bare `aiterprise-scan <path>` | working |
| Repository discovery (W2): requirements, pyproject (PEP 621 + Poetry), Pipfile(.lock), poetry.lock, uv.lock, environment.yml, package.json, package-lock v1–v3, pnpm-lock v5/v6/v9, yarn.lock v1/berry; Python/JS imports and notebooks. Lockfile wins over manifest; a range is never an exact version | `discover.py` | working |
| Component taxonomy (§4.2) | `data/ait/taxonomy.json`, `taxonomy.py` | working for libraries (a first-party, curated list of PyPI and npm names). Model files, model and dataset references, MCP servers and configs, agent skills, prompts, AI endpoints and vector stores are component types too (C02, below) |
| BOM ingest (C09): CycloneDX 1.4–1.7 (nested), SPDX 2.x JSON, UTF-8/UTF-16 with or without BOM; versionless components marked unjudgeable | `ingest.py` | working |
| Known-malicious versions (C14): OSV `MAL-` snapshot; exact, all-versions, range-admits-malicious, unpinned. Withdrawn records reported as `withdrawn`, never active, never dropped (§4.3) | `intel_malicious.py`, `data/ait/malicious-versions.json.gz` | working — 235,492 records (npm 223,463 · PyPI 12,029) + 363 withdrawn, built 2026-11-16. Every scan loads the snapshot; its index keys only the ~100 names that normalize to another spelling and looks the rest up in the snapshot's own tables, so loading it costs 0.03 s instead of 0.47 s (an offline scan of the five-file killer-demo repository: 1.18 s instead of 1.77 s, Windows, Python 3.11; 10 deliberate breaks of the index are each caught by a test) |
| Slopsquatting and registry checks (C15–C16): names that do not exist on PyPI/npm, packages under 72 h old, pinned versions that do not exist, npm security holders; a release under 30 days old after two quiet years (`dormant-release`) or with a major version 10 or more above every earlier one (`version-jump`); lookalike names of popular and AI packages, with the kind of slip named (separator, lookalike letters, swapped, missing, doubled or adjacent-key letter) | `registry.py`, `data/ait/popular-packages.json` | working — measured on the names of 1,017 packages installed on one developer machine: the lookalike rule flags 2 (0.20 %; it flagged 6 before four of them, such as `psycopg` and `safer-buffer`, were listed as legitimate near names, so this is a rate after tuning on the same names); of the 364 PyPI packages, 131 had a release in the last 30 days and neither release signal fired on any. Release signals need publish times: on npm only packages with at most 5 versions are read in full. A name one keystroke from a 4-letter popular name is judged only online (under a year old): 177 of 605 such npm variants exist, `xlsx` among them |
| Publisher signals (C17): the release in use is unsigned though the release before it was signed (`provenance-dropped`: a PEP 740 attestation on PyPI; trusted publishing or `--provenance` on npm), or it came from someone new (`publisher-change`: on npm a publisher who was neither a maintainer nor the publisher of the release before; on PyPI an attestation from another repository) | `registry.py` | working — judged only for a release from the last 30 days, compared with the previous release in version order (so a backport is compared with its own line). On the same 1,017 names: 317 recent releases (130 PyPI, 72 of them attested along with the release before; 187 npm), `provenance-dropped` fired on none, `publisher-change` on 2 (0.63 %), both real hand-overs within an organization (`tslib` now published by a Microsoft account, `source-map` by a new Mozilla maintainer). npm has no per-version times in the abbreviated document, so `latest` counts as recent when the package document changed in the last 30 days |
| Vulnerabilities (C19): OSV querybatch → per-advisory details, cached, alias de-duplication, CVSS v3 base score, fix-version advice | `vulns.py`, `net.py`, `cache.py` | working (verified live against api.osv.dev) |
| Offline advisory subset: OSV advisories for the 164 AI-taxonomy packages, used offline and when OSV is unreachable | `data/ait/vuln-subset.json.gz` | working — 2,921 advisories over 65 packages, built 2026-11-16 |
| Exploitation priority (C20): CISA KEV upgrades to critical | `vulns.py`, `data/ait/kev.json` | working — 1,781 CVEs, catalog 2026.11.13 |
| Model files (C21): pickle opcode walk (protocol 0–5, raw, legacy torch, PyTorch zip/TorchScript, `.mar`, `.npz`, `.npy`, joblib), safetensors, GGUF chat-template SSTI, ONNX custom ops / external data, Keras v3 / HDF5 `Lambda`, TFLite/`.pte` inventory; zip-slip; caps — never unpickled | `modelfiles.py`, `data/ait/model-rules.json` | working — verified on hand-built samples only (see limits) |
| Known-bad model hashes (C23, the MVP seed list): a model file whose SHA-256 or SHA-1 a public incident report names is reported (`ait.model.known-bad-hash`, high, malicious) with the report's link, offline. The bytes are checked before the format, so an ELF named `syscore.bin` is reported though it is no model | `knownhashes.py`, `data/ait/known-bad-hashes.json` | working — 11 files from 3 reports; every hash, file name, repository and size was checked against the saved report page. No listed file was obtained, so no match on a real file was seen; the tests use stand-in entries (see limits) |
| Package archives: wheels, sdists, tarballs, eggs, MCPB/DXT bundles — `.pth` payloads, `setup.py` / npm lifecycle commands, path traversal, model members | `archives.py`, `mcpb.py` | working |
| Model / dataset licence verdicts (C25) against `use_context`, base-model inheritance, allow/deny | `licences.py`, `data/ait/licence-verdicts.json` | working (advisory, not legal advice) |
| Package licences (§5.3) in the BOM and the reports: from `package-lock.json` (v2/v3) offline; online, each pinned PyPI or npm package still without one from deps.dev's version endpoint, cached, with its own coverage entry | `discover.py`, `pkglicences.py`, `registry.RegistryClient.depsdev_version` | working — recorded only: no verdict is drawn from a package licence. deps.dev's stable API gives `non-standard` for a licence it cannot map to SPDX (flask 3.0.0 among them, 2026-11-17); those are left empty and named in a note. pnpm, yarn and Python lockfiles record no licence, so their packages get one online only |
| MCP configs (C26/C29/C31): Claude Desktop/Code, Cursor, VS Code (JSONC), Codex TOML, Windsurf, Gemini, OpenClaw (`openclaw.json`, JSON5), DeepSeek Harness (`$DSH_HOME/profiles/*/cordis.patch.yml`, YAML; a `!!js process.env.X` value is an environment reference, not a literal); dangerous commands, poisoned descriptions, literal secrets, scope, plain-http — nothing launched (G8) | `mcp.py`; the rule sets, shared with skills, MCP bundles and package archives, in `textrules.py` with `data/ait/command-rules.json` (57), `data/ait/poison-patterns.json` (20) | working — one rule makes the same finding wherever its text was found |
| Agent skills / plugins (C30/C31); with `--agent-configs` also the skills folders of the machine: `~/.claude/skills`, `~/.claude/commands`, `~/.codex/skills`, `~/.agents/skills`, OpenClaw's managed and workspace skills and its `skills.load.extraDirs` | `skills.py` | working — on one developer machine `mcp --agent-configs` read 3 agent configs, 4 MCP servers and 156 skills and commands (115 distinct names) in 7.5 s offline. Not read: Claude Code's plugin folder, which holds whole marketplaces (mostly plugins nobody installed); folders starting with a dot, such as a `.trash` of deleted skills. OpenClaw and DeepSeek Harness are checked against their published documentation only — neither is installed on that machine |
| AI secrets (C32), redacted, digest-keyed | `secrets.py` | working |
| Prompts, AI endpoints and vector stores (C02): agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, Copilot, Cursor, Windsurf, Cline, Kiro and other rule folders), sub-agents and their tool grants, commands, prompt templates, hub prompts pulled by a literal id; the provider APIs the code calls (45 hosts and patterns), endpoint variables, Dockerfile `ENV` and an AI client's `base_url`; vector stores by container image, client call or store file on disk. All three are `data` components in the CycloneDX BOM, inventory only (no rule fires on them) | `prompts.py`, `services.py`, `data/ait/ai-assets.json` | working — a prompt's text is never copied, and an endpoint is kept as its origin only (credentials, path and query cut). Test code, fixtures, docs and comment lines are not the application, so nothing found there is listed (an instruction file in a test folder still is). On 13 local projects (about 210,000 files) it listed 19 components: 17 endpoints and 2 instruction files, each a real reference to an AI service, one of them an example in a help string; none of those projects uses a vector store, so vector-store detection is checked on test fixtures only. A full offline scan of a 5,620-file project (warm file cache) took 19.2 s without these analyzers and 20.7–22.4 s with them |
| SecDB API v1 client (§4.8, Appendix I/K): `/v1/me` limits, lookups (single, batch on paid plans), MCP URL prefixes and assessments, file verdicts, data notices, FP reports with consent, report upload; budget from the plan; 429 → UNVERIFIED, never clean | `secdb.py`, `account.py`, `login` / `logout` / `status` / `report-fp` / `upload` | working — verified live with a free key (`/v1/me`, `/v1/usage`, lookups within the 4/min budget); batch and upload are plan-gated and not live-tested; `login --install` (anonymous install token) is tested against a stand-in only, never run against the live service; the named-MCP assessment call is in the client but is never made, because no analyzer sets a server's registry name (H.5 #1) |
| BYO-key third-party enrichment (C38, §6.4, K.8): `scan --byo virustotal=ENV_VAR` looks up the SHA-256 of the model files and package archives of a scan directly at VirusTotal with the customer's own key. FD22 guards: hash lookups only (no upload path), no cache, findings under `ext.virustotal.*` with a null FP rate and never our `malicious` verdict, left out of everything sent to SecDB or a cloud, redirects refused, the key in no output; quota, refused key, outage, budget and `--offline` are reported as not verified, never clean | `providers/`, `docs/providers.md` | working against a local stand-in (72 tests) — **no live VirusTotal call was made** (no key), so the response shape is from the public API documentation only |
| Signed definition bundles (C50): minisign (pure-Python Ed25519, RFC 8032) over the manifest, root-signed `signing-keys.json` with rollback and expiry checks, `release_id` from JCS, archive hash before unpack, atomic install, rollback, per-load re-check. The report names the release a scan used (`release_id`, which the cloud already stores); `--defs-version rel_…` (or `AITERPRISE_DEFS`) pins an installed release for a repeatable audit, all or nothing: a manifest that does not hash to the id or a changed file stops the scan (exit 2) | `ed25519.py`, `minisign.py`, `bundles.py`, `defscli.py`, `defs verify/install/update/rollback`, `tools/build_bundle.py` | working — a locally built bundle verified, installed and used; the pin is tested with locally built releases only, since SecDB publishes none yet; interop with the reference `minisign` passes both ways in CI. Only `.tar.gz` bundles were exercised: a `.tar.zst` bundle (the design's format, §5.4) needs Python 3.14+, and the image, the binaries and the Action run 3.12 |
| Rule quality: per-finding `fp_rate_measured` (measured, or null) and `examined` coverage counts | `quality.py`, `data/ait/rule-quality.json`, `tools/measure_fp.py` | working — `ait.secret.*` measured (3.41 % over 205 clean projects) and `ait.skill.*` measured (11.64 % of 275 installed agent skills trip a skill rule; per-rule rates are in the file); MCP, model-file and archive rules are `null` |
| CycloneDX 1.7 emission (C05), 1.6 compatible, findings as `vulnerabilities[]` | `bom.py`, `--emit-bom`, `bom` command | working |
| Reports: table, JSON, SARIF 2.1.0, self-contained HTML; data notices | `report.py`, `reportdoc.py`, `html_report.py` | working — the JSON report is the report document: one module (`reportdoc.py`) owns its layout, its `schema` (`aiterprise-report/1`) and the upload view (no third-party provider results, no local paths), which the SecDB client applies to everything it sends. `--out` takes a directory of named reports, or, with one `--format`, the report file itself (`--format sarif --out results.sarif`) |
| Policy (C33), suppressions with mandatory expiry (C34), `.snyk` import, baseline (C35); malicious findings accepted only by an expiring fingerprint suppression; UI suppressions in `.aiterprise/suppressions.json` | `policy.py`, `gate.py` | working — one gated scan (`gate.py`) decides pass or failure for the CLI, the UI and the MCP tool: the policy, the project's suppressions and the baseline are read from the scanned project's directory, also for a single-file target |
| Org policy sync and cloud upload: `policy pull` (ETag, refuses a policy this scanner cannot load), `scan --upload --cloud`, `upload --cloud`; keys only over https (http to loopback only), and a request that carries a key never follows a redirect | `cloudpolicy.py`, `account.py` | working — verified end to end against a local `aibom-cloud` with a real SecDB key (upload 201, pull 200 then 304) |
| Coverage honesty: skipped files are `ait.*.not-analysable` findings; an unreachable source exits 2 | `model.not_analysable`, `scanner.py`, `sources.py` | working — every source is named once in `sources.py`, with the rule families it raises, and counts its own coverage; every judgement, the licence and deny-list ones included, is counted as a source; a test scans all golden fixtures and fails if a finding reports data from zero consulted sources |
| Local web UI: scan history, findings with filters, inventory, coverage, diff between scans, suppress, SecDB account, defs update; 127.0.0.1 only, token → HttpOnly cookie, Host check, CSRF + Origin, CSP nonce | `ui.py`, `history.py`, `ui`, `scan --save` | working — checked in a real browser, including a 375 px viewport |
| Local MCP server exposing `scan_ai_supply_chain` (C44), protocol 2025-06-18; registry manifest | `mcpserver.py`, `mcp serve`, `server.json` | working; `server.json` fits the registry schema (2025-12-11); not published to the MCP registry, which needs the PyPI release first. The tool goes through the same gate as the CLI and the UI; it never consults SecDB, and its coverage says so |
| Acceptance demo: five planted problems, one scan, offline and online; `--exe` holds a built binary to the same five | `tools/killer_demo.py` | working — 5/5 from source offline and online in CI (the online run fails unless the report shows OSV and the registries answered; without a network it would still find all five from bundled data, so the check is what makes it an online test), and from the six binaries in CI (Linux, macOS and Windows, each x86-64 and arm64) |
| Packaging: wheel + sdist, single-file binaries (PyInstaller), container image, Sigstore-signed release, self-SBOM, PyPI trusted publishing | `packaging/`, `Dockerfile`, `.github/workflows/release.yml`, `binaries.yml` | wheel, sdist, self-SBOM and container image built and checked in CI; CI builds the six binaries (Linux, macOS and Windows, each x86-64 and arm64, natively on its own runner) with the release's own `binaries.yml` and each passes the killer demo (5/5, exit 1); the tag-triggered release (signing, PyPI, ghcr.io) **not yet run** — `RELEASING.md` lists the one-time setup it needs (a PyPI trusted publisher; the name is free) |
| FP methodology page (§10.6 #7): what a rate means, the three corpora and their limits, how to reproduce; coordinated disclosure policy, 90 days by default (§8.4); contributions under the DCO (W1) | `docs/fp-methodology.md`, `SECURITY.md`, `CONTRIBUTING.md` | written — the DCO sign-off is asked for, not checked by CI; the disclosure policy names no `security.txt` yet |
| Scan speed (§5.5): `tools/bench_scan.py` builds a 10,000-file monorepo (Python standard-library sources, TypeScript, manifests, configs and READMEs, with the killer demo's five problems in one package) and times two offline scans by the CLI, each in a new process: a cold one, then a re-scan of the unchanged tree; CI fails when the first takes over 60 s, the second over 10 s, or either misses a problem. CI then does the same online (`--online`: OSV, the package registries and deps.dev asked, no SecDB) against 120 s cold and 10 s for the re-scan, and also fails unless every report shows that all three were consulted. A scan reads each file once (`textio.read_once`, up to 256 MB of text kept for the other analyzers), and the import, secret, model-reference and endpoint analyzers skip a file that cannot match before parsing it: an import needs an AI package's name starting a name right after `import` or `from` at a statement's start (checked on the source as Python reads it, NFKC-normalised; a file with a dynamic import is always parsed), a key its prefix, a regex its literal. On 9,763 Python files of three installed environments this parses 1,043 files instead of 3,963 for the same imports found. Between scans, what the import, endpoint, model-reference and secret analyzers found in each file is kept under the file's SHA-256 (`AITERPRISE_CACHE_DIR/scan`, one file per analyzer and target), valid only for the same build of the scanner and the same definitions release; a re-scan still reads every file but takes an unchanged file's results from there instead of analysing it again, and the report says how many. A secret is kept as the report shows it (rule, line, redacted preview, 8-character digest), never its value; whether a model id in code names a folder of the tree is checked on every scan. Judging runs in full every time; `--no-cache` turns it off | `tools/bench_scan.py`, `textio.py`, `scancache.py`, CI job `benchmark` | working — in CI (GitHub's Ubuntu runner, Python 3.12, 10,000 files, 166 MB) the latest run took 7.5 s cold and 4.1 s to re-scan offline, 9.3 s and 4.2 s online (2026-11-17, before deps.dev was asked). With only imports and endpoints kept, two runs of the same code took 9.4 s / 6.6 s and 14.6 s / 9.0 s offline, which is how much the runner varies; that margin is why model references and secrets are kept too. On the Windows development machine (Python 3.11, 10,000 files, 166 MB) the re-scan takes 4.4 s (6.1 s with only imports and endpoints kept, 21.7 s with nothing kept) and the cold scan 49.8 s, much of it the system opening freshly written files for the first time (reading every file of the tree takes 55.6 s the first time and 0.7 s the second). Same findings: 84 deliberate breaks of the shortcuts and of the kept results are each caught by a test |
| Model-file speed (§5.5): `tools/bench_models.py` writes a 2 GiB `.safetensors`, a 1 GiB PyTorch zip and a 1 GiB raw pickle of random bytes and times an offline scan of each by the CLI, each in a new process; CI fails when a scan takes longer than the design's budget (2.5 s per GiB for safetensors, 30 s per GiB for the two pickle formats), exits non-zero, misreads the format or misses the pickle finding. A model file's SHA-256 and SHA-1 are computed in two threads over 4 MiB reads | `tools/bench_models.py`, `modelfiles.py`, CI job `benchmark` | working — in CI (GitHub's Ubuntu runner, Python 3.12, run of 2026-11-17) the 2 GiB safetensors takes 4.5 s of its 5.0 s budget, the zip pickle 3.3 s of 30 s and the raw pickle 3.6 s of 30 s, at 240 MB peak memory. The safetensors budget is the tight one: a slower runner may fail it. Not run at full size on the development machine, which lacks the free disk |
| CI: test matrix, wheel and sdist, self-scan, killer demo, scan and model-file benchmarks, licence check, minisign interop, docs, container, binaries, the GitHub Action, the GitLab template, the pre-commit hook | `.github/workflows/ci.yml` | working — green on `main` |
| Scheduled definition refresh (MAL + KEV + advisory subset) | `.github/workflows/refresh-defs.yml` | working — weekly. The first scheduled run (2026-11-16) rebuilt the data, passed the full tests and the killer demo on it, and opened the refresh pull request itself (the repository lets Actions create pull requests); it was merged the same day. CI on such a pull request starts only when it is closed and reopened |
| Per-record licence check of the redistributed OSV records (H.3) | `tools/osv_terms.py`, both builders, `tests/test_record_terms.py` | working — only `MAL`, `GHSA` and `PYSEC` records ship; every shipped id is checked by a test that the refresh runs before proposing new data (see *Record licences*) |
| Documentation site (MkDocs, strict build); generated rules reference | `mkdocs.yml`, `docs/`, `tools/gen_rules_doc.py` | working — builds locally with `--strict` |
| VS Code / Cursor tasks (C45): scan the workspace into the Problems panel, the machine's MCP servers and skills, the full report, the dashboard; GitLab CI job (S3): Code Quality widget, table in the log, CycloneDX 1.6 AI-BOM report | `templates/vscode/tasks.json`, `templates/gitlab/aiterprise-scan.gitlab-ci.yml`, `--format compact`, `--format codequality`, `docs/integrations.md` | working in tests — every task's and the job's command line is accepted by the CLI parser, and the tasks' problem matcher reads every line of a real scan. **Not run in VS Code or on GitLab**: the Code Quality and CycloneDX reports follow GitLab's documentation only |
| GitHub Action (with optional `api-key`), pre-commit hook; the Action's pull-request comment and job summary (C42): one comment per pull request, found again by its marker and its author and updated in place, scanned text shown as code; a read-only token (a fork's pull request) warns and the gate still decides | `action/`, `action/pr_comment.py`, `--format markdown`, `.pre-commit-hooks.yaml` | working — CI uses the action on the killer-demo repository (the gate fails, `exit-code` 1, report, SARIF and AI-BOM written) and on a clean fixture (`exit-code` 0), then checks that the pull request carries exactly one comment and that it shows the clean scan; `pre-commit try-repo` runs the hook on both. Not exercised: the SARIF upload to code scanning (not available to a private repository) and the `api-key` input |
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
| Installed Claude Code plugins of the machine; Hermes Agent configs | §4.1 | not built — the plugin folder mixes installed and offered plugins, and no index of the installed ones was found on the machine checked |
| Single-maintainer and download-count signals; a change of trusted-publisher repository on npm (the registry shows only that trusted publishing was used); crates.io; GuardDog's metadata rules that need package contents or maintainer e-mail domains | C16 / C17 | not built — registry checks are existence, age, release timing and who published |
| Named-MCP assessments used by `scan`; a static tool-list parser | H.5 #1 / K.3 / C26 | the client call exists and is never made; the parser is not built |
| SkillSpector integration | G3 / C30 | not built — the skill analyzer has its own 0–100 risk score |
| Opt-in telemetry (rule ids and counts) | §4.8 | not built — there is no telemetry code at all |
| False-positive corpus of at least 200 AI repositories and 500 real model files; automatic demotion of a noisy rule | §5.5 | not built — the corpora are local site-packages projects and installed skills; a critical rule with a measured FP rate above zero still reports critical |
| Process-pool parallelism | §5.5 | not built — one process does all the work; the cold-scan and re-scan targets are met without it (see *Scan speed*) |
| `security.txt`; function-parity matrix | §10.6 #7 / §8.4 | not built — `security.txt` needs a contact the project has not chosen (GitHub's private vulnerability reporting is not available while the repository is private); the parity matrix would make claims about other products that are not verified |
| Device-code login | J.3 | blocked on the platform Console — login is a pasted key or an install token |
| `watch` command | S6 | not built |

## Definition data

| Asset | Content | Input (provenance) | Size |
|---|---|---|---|
| `malicious-versions.json.gz` (schema `ait-malicious-versions/2`) | 235,492 active `MAL-` records over 235,491 packages; 214,803 mark every version, the rest list 65,677 exact versions; 363 withdrawn records kept apart | OSV bulk exports `PyPI/all.zip` and `npm/all.zip`, 2026-11-16 — SHA-256 of each input recorded in the file and shown by `defs status` | 3.06 MB |
| `vuln-subset.json.gz` (schema `ait-vuln-subset/1`) | 2,921 advisories for 65 of the 164 AI-taxonomy packages | Same OSV exports; GHSA and PYSEC records only, both CC-BY 4.0 (see *Record licences* below) | 0.24 MB |
| `kev.json` | 1,781 CVEs | CISA KEV catalog 2026.11.13 (CC0) | 0.3 MB |
| `known-bad-hashes.json` | 11 files: 7 with SHA-256, 7 with SHA-1 (3 have both) | Rapid7, "From .pth to p0wned" (2025-07-01); ReversingLabs, nullifAI (2025-02-06, SHA-1 only); Pluto Security, "Load/Mine" (2026-10-29). Hashes copied verbatim; each entry carries its report's URL | 6 KB |
| `rule-quality.json` | measured FP rates; a command rule or poison pattern that never fired on a measured corpus is written at 0 | `tools/measure_fp.py` over 210 local site-packages projects (secrets) and 275 installed agent skills (skills) | 31 KB |

The counts above are the 2026-11-16 build, made by the first scheduled refresh (16 more `MAL-`
records than the 2026-11-14 build it replaced). Every weekly refresh changes them;
`aiterprise-scan defs status` prints what a given build carries.

Quality checks on the malicious snapshot: no withdrawn record is active (`fastapi 0.136.3` is
reported as `withdrawn`, exit 0); popular packages carry exact-version records only (axios
0.30.4/1.14.1, chalk 5.6.1, debug 4.4.2, litellm 1.82.7/1.82.8/1.107.0, …), pinned by a unit test;
two real npm lockfiles (877 packages) scanned offline with zero malicious findings (that scan was
made on the 2026-11-14 build).

Record licences (design doc 13, H.3): an OSV record's id prefix names the database it comes from,
and each database has its own licence. `tools/osv_terms.py` lists the databases the wheel may
carry — `MAL` (OpenSSF Malicious Packages, Apache-2.0), `GHSA` (GitHub Advisory Database,
CC-BY 4.0) and `PYSEC` (PyPI Advisory Database, CC-BY 4.0), each checked against osv.dev's list of
data sources on 2026-11-17. Both builders drop every other record and write `terms` (each database,
its licence and URL, and a record count) and `excluded` (the count left out per prefix) into the
file; NOTICE carries the attribution. Prefixes not listed are left out until someone reads their
terms; Chainguard's `CGA-` (CC-BY-NC-ND 4.0) and Ubuntu's (CC-BY-SA 4.0) are known and left out on
purpose. `tests/test_record_terms.py` checks every record id in the shipped files, so a refresh that
would ship any other record fails before its pull request is opened. The files built before this
check (2026-11-16) carry only `MAL`, `GHSA` and `PYSEC` records; their `terms` field appears at the
next refresh.

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
- **Poison patterns 9–20** (2026-11-17) each match a published tool-poisoning technique in
  `tests/test_textrules.py`, and fire on none of the 275 skills. Over 1,771 Markdown and text docs
  of installed Python and npm packages they fire 7 times: chat-template tokens in three docs about
  model formats (so that rule is medium, not high), two skills telling the agent to use
  `--dangerously-skip-permissions`, and two real Latin/Cyrillic mixes (a jailbreak demo and a typo).
  That second corpus is not in `rule-quality.json`: a package doc is not text an agent is told to follow.
- **Known-bad hashes** (2026-11-17) match exact bytes only: a re-saved or re-compressed copy of a
  listed file does not match, and the pickle and format rules have to catch it. Only files with a
  model-file extension are hashed, so the same reports' loader scripts (`modeling_*.py`,
  `configuration_*.py`), `e.sh` and `sysd-kit.tgz` are left out of the list. JFrog's and NSFOCUS's
  reports publish no hashes, and Rapid7 gives none for `8TX8.pth`. ReversingLabs names its two
  files of each repository "PyTorch file" and "Pickle file" only; the pickle is the member inside the
  7z archive, so it matches only when someone has extracted it as a file.
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
