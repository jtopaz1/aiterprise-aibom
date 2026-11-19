# Quickstart

## Install

```bash
pipx install git+https://github.com/jtopaz1/aiterprise-aibom@v0.1.0      # or: pip install git+https://github.com/jtopaz1/aiterprise-aibom@v0.1.0
```

Other ways, all from the same release:

- a single-file binary for Linux, macOS or Windows (x86-64 or arm64) from the [v0.1.0 release](https://github.com/jtopaz1/aiterprise-aibom/releases/tag/v0.1.0).
  Each file is listed in `SHA256SUMS` and has a Sigstore bundle made by the release workflow at the tag:

  ```bash
  cosign verify-blob --bundle aiterprise-scan-linux-x86_64.sigstore.json \
    --certificate-identity https://github.com/jtopaz1/aiterprise-aibom/.github/workflows/release.yml@refs/tags/v0.1.0 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com aiterprise-scan-linux-x86_64
  ```

- the container image: `docker run --rm -v "$PWD:/src" ghcr.io/jtopaz1/aiterprise-scan:0.1.0`.

## First scan

```bash
aiterprise-scan .
```

The table report ends with a result line and the process exits with:

| Exit | Meaning |
|---|---|
| `0` | no new finding at or above `--fail-on` (default `high`) |
| `1` | policy failure — at least one such finding |
| `2` | error or incomplete scan: an analyzer failed, or a source such as OSV could not be reached |

`--offline` uses only the bundled definitions and the local cache; it is not an error. Files the
scanner had to skip are reported as `ait.*.not-analysable` findings — never passed as clean.

## Reports

```bash
aiterprise-scan . --format json --format sarif --out reports/
aiterprise-scan . --emit-bom aibom.cdx.json       # CycloneDX 1.7 AI-BOM with findings
aiterprise-scan . --format html --out reports/    # one self-contained page
aiterprise-scan . --save && aiterprise-scan ui    # keep it in the local history
```

## Other targets

```bash
aiterprise-scan scan --bom cdxgen-aibom.json            # judge someone else's AI-BOM
aiterprise-scan scan dist/mypkg-1.0-py3-none-any.whl    # a package before you publish or install it
aiterprise-scan scan models/model.pt                    # one model file
aiterprise-scan mcp --agent-configs                     # this machine's MCP servers and skills
```

## CI

GitHub Action (comments the findings on the pull request, writes the job summary, uploads SARIF to code scanning, then gates):

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write          # the pull-request comment
  security-events: write        # the SARIF upload
jobs:
  aibom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jtopaz1/aiterprise-aibom/action@v0.1.0
        with:
          fail-on: high
          api-key: ${{ secrets.AITERPRISE_API_KEY }}   # optional: SecDB judgements
```

The comment lists the new findings (suppressed and baselined ones are only counted) and is
updated in place on every push, never posted twice. Scanned text in it is shown as code, so a
hostile package name or tool description cannot mention people, load images or break the table.
A pull request from a fork gets a read-only token: the action then warns and leaves the report in
the job summary, and the gate still decides. `comment: "false"` and `job-summary: "false"` turn
either off.

pre-commit:

```yaml
- repo: https://github.com/jtopaz1/aiterprise-aibom
  rev: v0.1.0
  hooks: [{ id: aiterprise-scan }]
```

Adopting on a project with existing findings: write a baseline once, then only new findings fail.

```bash
aiterprise-scan . --write-baseline .aiterprise/baseline.json
aiterprise-scan . --baseline .aiterprise/baseline.json
```

## The acceptance demo

`python tools/killer_demo.py` builds a small repository with five planted problems — the
compromised `litellm 1.82.7`, `transformers 4.44.0` with a known CVE, a `model.pt` whose pickle
runs a shell command, an MCP server with a poisoned tool description, and a Llama 3 model under its
conditional licence — and passes only if one offline scan finds all five and exits 1. With
`--online` the scan also asks OSV, the package registries and deps.dev, and the demo fails unless
the report shows they answered. CI runs both on every push; the release runs it against the container image and
every binary.
