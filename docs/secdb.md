# SecDB

[SecDB](https://secdb.aiterprise.net) is AIterprise's threat-intelligence service. The scanner works
fully without it; logged in, it also asks SecDB about:

- **model-file hashes** — a SHA-256 known to be malicious or suspicious (`ait.model.hash.*`);
- **private MCP server URLs** — sent only as an 8-hex SHA-256 prefix; the URL never leaves the
  machine, and matching happens locally (`ait.mcp.secdb.*`);
- **named MCP servers** — a provenance assessment (`ait.mcp.reputation.*`); `clean` is never
  reported as safe. Not requested by a scan yet: nothing gives a server found in a config its
  registry name, so only the URL-prefix check above runs for MCP servers;
- **packages** — SecDB's verdict (`ait.pkg.secdb.*`), AI packages first.

## Log in

```bash
aiterprise-scan login                     # paste an API key (aik_…); checked with GET /v1/me first
aiterprise-scan login --key-stdin < key   # CI
aiterprise-scan login --install           # no account: an anonymous install token
aiterprise-scan status                    # plan, per-minute limit, usage this month
aiterprise-scan logout
```

The key is never printed. It is saved in `~/.aiterprise/credentials.json` — encrypted for the
current user with DPAPI on Windows, file mode 0600 elsewhere. In CI, set `AITERPRISE_API_KEY` from
a secret instead; it takes precedence over a saved key.

The key is sent to SecDB's own address only. A redirect from SecDB is refused, not followed, because
following it would send the key on to the new address; the same holds for an AIterprise cloud.

`login --install` needs no account. It registers this installation with SecDB — sending the
scanner's name and version and the operating-system family, nothing else — and saves the install
token SecDB returns in the same file. A key, from the environment or saved, is used before an
install token.

## Limits and what "unverified" means

The per-minute budget comes from your plan (`/v1/me`), not from a constant in the scanner. The
scanner spends it in priority order (files, MCP URLs, MCP names, AI packages, other packages).
When the budget or the monthly quota runs out, the items not looked up are listed in a note as
**UNVERIFIED, not safe** — never reported as clean. A `429` is not retried during a scan; `502` and
`503` are retried with back-off. A rejected key (`401`/`403`) skips SecDB for the rest of the scan
and says so.

Batch lookups and report upload need a paid plan. The free plan does single lookups only.

## Data notices

When SecDB returns attribution notices for the data it used, the reports reproduce them (the JSON
`notices` array, a "Data notices" section in the table and HTML reports).

## Upload

```bash
aiterprise-scan . --upload                       # after the scan (SecDB Pro+)
aiterprise-scan upload report.json --project api
aiterprise-scan . --upload --cloud https://aibom.example.com   # your AIterprise cloud
```

Before upload, the target becomes its directory name and home-directory paths become `~/…`. The
report holds component names, versions, hashes and findings — no source code.

## False positives

```bash
aiterprise-scan report-fp ait.mcp.cmd.pipe-to-shell --notes "the pipe is to a local file"
```

Sends the rule id and your notes, only after you consent (interactively, or `--yes`). Do not put
secrets or source code in the notes.

`--offline` and `--no-secdb` never call SecDB.
