# Changelog

Every release, newest first. A release's section here is the text of its GitHub release
(`tools/release_notes.py`). [`docs/STATUS.md`](docs/STATUS.md) says what is built and what is not.

## 0.1.0 — 2026-11-18

The first release. One command inventories the AI components of a repository, a model file, a
package archive, an agent configuration or someone else's AI-BOM, writes a CycloneDX AI-BOM, and
judges each component. Every finding carries its evidence, the sources that were consulted, and the
rule's measured false-positive rate where there is one. It runs offline, with no runtime dependencies.

### Install

- `pipx install git+https://github.com/jtopaz1/aiterprise-aibom@v0.1.0` (Python 3.11 or newer)
- a single-file binary from this release, for Linux, macOS or Windows on x86-64 or arm64
- `docker run --rm -v "$PWD:/src" ghcr.io/jtopaz1/aiterprise-scan:0.1.0`
- in CI: `uses: jtopaz1/aiterprise-aibom/action@v0.1.0`, or the pre-commit hook at `rev: v0.1.0`

PyPI refused this release's upload, so `pip install aiterprise-scan` does not find it yet.

Every file of the release is listed in `SHA256SUMS` and has a Sigstore bundle signed by the release
workflow at this tag:

```bash
cosign verify-blob --bundle aiterprise-scan-linux-x86_64.sigstore.json \
  --certificate-identity https://github.com/jtopaz1/aiterprise-aibom/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com aiterprise-scan-linux-x86_64
```

### What it judges

- **Packages:** known-malicious versions from OSV's `MAL-` records (235,492, bundled, so this works
  offline), version ranges that admit one, names that do not exist on PyPI or npm (slopsquatting),
  packages under 72 hours old, lookalike names, a release after years of silence or with a sudden
  major-version jump, a release that dropped its provenance or came from a new publisher.
- **Vulnerabilities:** OSV advisories per exact version, raised to critical when CISA KEV lists
  them; a bundled AI-package subset keeps this working offline.
- **Model files:** pickles that call dangerous functions (raw, or inside a PyTorch zip), Keras
  `Lambda` layers, ONNX custom operators, GGUF chat-template injection, malformed containers, and
  files that incident reports name by hash. Nothing is ever unpickled or loaded.
- **Package archives:** `.pth` start-up payloads, `setup.py` and npm lifecycle commands, path
  traversal, model files inside.
- **MCP servers:** the configs of every agent (Claude Desktop and Code, Cursor, VS Code, Codex,
  Windsurf, Gemini, and others), MCPB and DXT bundles, and the servers your own code builds:
  dangerous commands, poisoned tool descriptions, literal secrets. No server is ever launched.
- **Agent skills:** `SKILL.md` trees and Claude Code plugins: poisoned instructions and install
  commands.
- **Licences:** model and dataset licence verdicts (Llama, Gemma, OpenRAIL, Mistral, Qwen and
  others) against how you use them. Advisory, not legal advice.
- **Secrets:** AI-provider keys, reported redacted.

Prompts, AI endpoints and vector stores go into the AI-BOM without a verdict.

### Reports and gates

- Formats: table, JSON, SARIF, Markdown, HTML, GitLab Code Quality, and one line per finding; a
  CycloneDX 1.7 AI-BOM with the findings and licence verdicts.
- Exit 0, 1 or 2 against `--fail-on`. Baselines, and suppressions that need a reason and an expiry.
- `aiterprise-scan ui`: a local web UI with scan history, findings, diffs and suppressions.
- `aiterprise-scan mcp serve`: the scan as a tool for any MCP client.
- Where it runs: the CLI, the GitHub Action (a pull-request comment, SARIF, the job summary), the
  pre-commit hook, a GitLab CI template, and VS Code and Cursor tasks.

### Known limits

- False-positive rates are measured for the secret rules, the skill and command rules and some
  package rules. The MCP, model-file, archive and licence rules read "not measured" until there is
  a corpus to measure them on.
- Online mode asks OSV, the PyPI and npm registries and deps.dev; `--offline` asks nothing.
  [`docs/privacy.md`](https://github.com/jtopaz1/aiterprise-aibom/blob/main/docs/privacy.md) lists
  every network call.
