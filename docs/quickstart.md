# Quickstart

## Install

```bash
pipx install aiterprise-scan          # or: pip install aiterprise-scan
```

!!! note "Not released yet"
    Nothing is published so far, so the command above and the other ways below work from the first
    tagged release. Until then, install from a checkout of the repository with `pip install .`
    (see [Implementation status](STATUS.md)).

Other ways, all from the same release:

- a single-file binary for Linux, macOS or Windows from the GitHub release (each file has a
  Sigstore bundle and is listed in `SHA256SUMS`);
- the container image: `docker run --rm -v "$PWD:/src" ghcr.io/jtopaz1/aiterprise-scan:latest`;
- `uvx aiterprise-scan …` without installing.

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
aiterprise-scan mcp --agent-configs                     # this machine's MCP servers
```

## CI

GitHub Action (uploads SARIF to code scanning, then gates):

```yaml
- uses: jtopaz1/aiterprise-aibom/action@main
  with:
    fail-on: high
    api-key: ${{ secrets.AITERPRISE_API_KEY }}   # optional: SecDB judgements
```

pre-commit:

```yaml
- repo: https://github.com/jtopaz1/aiterprise-aibom
  rev: main
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
`--online` the scan also asks OSV and the package registries, and the demo fails unless the report
shows they answered. CI runs both on every push; the release runs it against the container image and
every binary.
