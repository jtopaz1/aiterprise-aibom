# Local web UI

```bash
aiterprise-scan ui                 # opens the browser
aiterprise-scan ui --no-browser    # prints the link instead
aiterprise-scan ui --port 8765     # a fixed port instead of a free one
```

The UI is served by the scanner itself on `127.0.0.1` only. It shows:

- **Scans** — every scan saved with `--save` or started from the UI, newest first; start a new
  scan of any local directory (offline or online).
- **A scan** — findings filtered by severity, verdict, status and text; the inventory; coverage
  (which sources were consulted and how many items had data); notes. Download the JSON report.
- **Diff** — what is new, fixed and unchanged between two scans, and which components were added
  or removed.
- **Suppress** — accept a finding with a reason and an expiry (at most 365 days). It is written to
  `.aiterprise/suppressions.json` in the scanned project; commit it so CI applies it.
- **Account** — log in to SecDB with an API key (checked before it is saved), see the plan and
  usage, log out; update the definition bundle.

History lives in `~/.aiterprise/history/` (one JSON report per scan) and can be deleted from the UI.

## Security

The UI can start scans and write files, so it is locked to the person who started it:

- it listens on `127.0.0.1` and refuses requests whose `Host` header is not that address;
- the link carries a one-time token that is exchanged for an `HttpOnly`, `SameSite=Strict`
  cookie; requests without it are refused;
- every form carries a CSRF token and every `POST` must come from the UI's own origin;
- pages are sent with a strict Content-Security-Policy (scripts only with a per-response nonce),
  `X-Frame-Options: DENY` and `Referrer-Policy: same-origin`.

Nothing is fetched from the internet to render a page.
