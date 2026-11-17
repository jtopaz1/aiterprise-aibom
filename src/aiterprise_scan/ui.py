"""`aiterprise-scan ui`: a local web UI on 127.0.0.1 (stdlib `http.server`, no external assets).

Pages: scan history, a scan's findings (filters, evidence, suppress-with-expiry), its inventory and
coverage, a diff between two scans, and the SecDB account and definition bundle.

Access control — the server listens on loopback only and still treats every request as hostile:
- a random token is printed once; opening `/?token=…` sets an HttpOnly, SameSite=Strict cookie;
  every request needs that cookie;
- the Host header must be `127.0.0.1:<port>` or `localhost:<port>` (DNS-rebinding defence);
- every POST needs the CSRF field and, when the browser sends one, a same-origin Origin header;
- responses carry a strict Content-Security-Policy (scripts only by per-response nonce) and
  `Cache-Control: no-store`.
Everything displayed comes from scanned, untrusted content, so every value is HTML-escaped.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import hmac
import io
import json
import secrets
import sys
import threading
import webbrowser
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from . import TOOL_NAME, __version__, credentials, history, reportdoc, secdb
from . import policy as policy_mod

COOKIE = "aiterprise_ui"
MAX_BODY = 64 * 1024
SEVERITIES = ("critical", "high", "medium", "low", "info")
VERDICTS = ("malicious", "suspicious", "vulnerable", "risky", "unknown")

_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#e3e6ea;--card:#f6f8fa;--accent:#2f6db5;--ok:#1f7a3f;
--critical:#b3261e;--high:#d1490b;--medium:#a86b00;--low:#2f6db5;--info:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--fg:#e6e8eb;--muted:#9aa3ad;--line:#2a2f36;
--card:#191d22;--accent:#6ea8ff;--ok:#5cc98a;--critical:#ff6b61;--high:#ff8a4c;--medium:#e0b341;--low:#6ea8ff;
--info:#9aa3ad}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{border-bottom:1px solid var(--line);background:var(--card)}
header .in{max-width:1180px;margin:0 auto;padding:10px 16px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
header b{font-size:15px}header a{color:var(--fg);text-decoration:none}header a.on{color:var(--accent);font-weight:600}
main{max-width:1180px;margin:0 auto;padding:20px 16px 60px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:26px 0 8px}
a{color:var(--accent)}.meta,.small{color:var(--muted);font-size:12.5px}
.tiles{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:92px}
.tile b{display:block;font-size:20px}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}
.sev{font-weight:700;text-transform:uppercase;font-size:11.5px;white-space:nowrap}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}
.info{color:var(--info)}.okc{color:var(--ok)}
code,pre{font:12px ui-monospace,SFMono-Regular,Consolas,monospace}code{word-break:break-all}
pre{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px;overflow-x:auto;
white-space:pre-wrap;word-break:break-all;max-height:320px}
form.inline{display:inline}input,select,button,textarea{font:inherit;color:inherit}
input[type=text],input[type=date],input[type=password],select{background:var(--bg);border:1px solid var(--line);
border-radius:6px;padding:5px 8px;max-width:100%}
button{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:6px 12px;cursor:pointer}
button.ghost{background:transparent;color:var(--accent);border:1px solid var(--line)}
button.danger{background:var(--critical)}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:10px 0}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:16px 0 8px;flex-wrap:wrap}
.tabs a{padding:6px 12px;text-decoration:none;color:var(--muted);border-bottom:2px solid transparent}
.tabs a.on{color:var(--fg);border-color:var(--accent)}
details summary{cursor:pointer;color:var(--accent)}details .box{padding:6px 0 10px}
.chip{display:inline-block;border:1px solid var(--line);border-radius:10px;padding:0 7px;margin:1px;font-size:12px}
.notice{background:var(--card);border-left:3px solid var(--medium);padding:8px 12px;margin:10px 0}
.err{border-left-color:var(--critical)}.okb{border-left-color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}
@media (max-width:640px){td.hide,th.hide{display:none}}
"""


def _e(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def quality_text(quality) -> str:
    """`quality` as one line: a measured false-positive rate with its corpus, or 'not yet measured'."""
    if not isinstance(quality, dict) or quality.get("fp_rate_measured") is None:
        return "false-positive rate not yet measured"
    rate = float(quality["fp_rate_measured"]) * 100
    where = f" on {quality['corpus']}" if quality.get("corpus") else ""
    scope = " (rule family)" if quality.get("scope") == "family" else ""
    return f"false-positive rate {rate:.1f}%{scope}{where}"


def _sev_chips(counts: dict) -> str:
    parts = [f'<span class="chip {s}">{counts.get(s, 0)} {s}</span>' for s in SEVERITIES if counts.get(s)]
    return "".join(parts) or '<span class="small okc">no active findings</span>'


class Job:
    def __init__(self, path: str) -> None:
        self.id = secrets.token_hex(6)
        self.path = path
        self.status = "running"
        self.scan_id: str | None = None
        self.error: str | None = None
        self.started = dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S")


class UIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, addr, token: str) -> None:
        super().__init__(addr, Handler)
        self.token = token
        self.csrf = hmac.new(token.encode(), b"csrf", hashlib.sha256).hexdigest()
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.flash: list[tuple[str, str]] = []

    @property
    def port(self) -> int:
        return self.server_address[1]

    def serve_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, name="aiterprise-ui", daemon=True)
        t.start()
        return t


def make_server(port: int = 0, token: str | None = None) -> UIServer:
    return UIServer(("127.0.0.1", port), token or secrets.token_urlsafe(32))


# --------------------------------------------------------------------------------------------
# Scanning from the UI
# --------------------------------------------------------------------------------------------

def run_scan_to_history(path: Path, offline: bool, registry: bool) -> str:
    from . import gate
    from .scanner import ScanOptions

    result = gate.gated_scan(ScanOptions(target=path, offline=offline, registry=registry))
    return history.save(reportdoc.build(result))


def _start_job(server: UIServer, path: Path, offline: bool, registry: bool) -> Job:
    job = Job(str(path))
    server.jobs[job.id] = job

    def work() -> None:
        try:
            with server.lock:  # one scan at a time
                job.scan_id = run_scan_to_history(path, offline, registry)
            job.status = "done"
        except Exception as err:  # noqa: BLE001 - reported on the job page
            job.status = "error"
            job.error = f"{type(err).__name__}: {err}"

    threading.Thread(target=work, name=f"scan-{job.id}", daemon=True).start()
    return job


# --------------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server: UIServer
    server_version = "aiterprise-ui"
    sys_version = ""

    def log_message(self, fmt, *args) -> None:  # quiet: paths may carry tokens
        pass

    # plumbing ---------------------------------------------------------------------------
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        return host in {f"127.0.0.1:{self.server.port}", f"localhost:{self.server.port}"}

    def _cookie(self) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return v
        return ""

    def _authed(self) -> bool:
        return hmac.compare_digest(self._cookie().encode(), self.server.token.encode())

    def _send(self, status: int, body: str | bytes, ctype: str = "text/html; charset=utf-8",
              headers: dict | None = None, nonce: str | None = None) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        script = f"'nonce-{nonce}'" if nonce else "'none'"
        style = f"'nonce-{nonce}'" if nonce else "'unsafe-inline'"
        self.send_header("Content-Security-Policy",
                         f"default-src 'none'; script-src {script}; style-src {style}; img-src 'self' data:; "
                         "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; connect-src 'self'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _redirect(self, location: str, headers: dict | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _plain(self, status: int, text: str) -> None:
        self._send(status, text, "text/plain; charset=utf-8")

    def _page(self, title: str, body: str, active: str = "", status: int = 200) -> None:
        nonce = secrets.token_urlsafe(12)
        nav = "".join(f'<a href="{href}" class="{"on" if key == active else ""}">{label}</a>'
                      for key, href, label in (("scans", "/", "Scans"), ("diff", "/diff", "Diff"),
                                               ("account", "/account", "Account")))
        flash = "".join(f'<div class="notice {cls}">{_e(msg)}</div>' for cls, msg in self.server.flash)
        self.server.flash.clear()
        html = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>{_e(title)} · AIterprise AIBOM</title><style nonce="{nonce}">{_CSS}</style></head><body>'
                f'<header><div class="in"><b>AIterprise AIBOM</b>{nav}'
                f'<span class="small" style="margin-left:auto">{_e(TOOL_NAME)} {_e(__version__)} · local only</span>'
                f'</div></header><main>{flash}{body}</main>'
                + self._script(nonce) + "</body></html>")
        self._send(status, html, nonce=nonce)

    def _script(self, nonce: str) -> str:
        return getattr(self, "_extra_script", "").replace("{nonce}", nonce)

    def _csrf_field(self) -> str:
        return f'<input type="hidden" name="csrf" value="{self.server.csrf}">'

    # dispatch ---------------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._plain(403, "forbidden host")
        url = urlsplit(self.path)
        q = {k: v[-1] for k, v in parse_qs(url.query).items()}
        if "token" in q:
            if hmac.compare_digest(q["token"].encode(), self.server.token.encode()):
                return self._redirect(url.path or "/", {
                    "Set-Cookie": f"{COOKIE}={self.server.token}; HttpOnly; SameSite=Strict; Path=/"})
            return self._plain(401, "invalid token")
        if not self._authed():
            return self._plain(401, f"Open the link that `{TOOL_NAME} ui` printed (it carries a one-time token).")
        path = url.path
        try:
            if path == "/":
                return self.page_index()
            if path.startswith("/scan/"):
                return self.page_scan(path[len("/scan/"):], q)
            if path == "/diff":
                return self.page_diff(q)
            if path == "/account":
                return self.page_account()
            if path.startswith("/jobs/"):
                return self.page_job(path[len("/jobs/"):])
            if path.startswith("/api/jobs/"):
                job = self.server.jobs.get(path[len("/api/jobs/"):])
                if job is None:
                    return self._plain(404, "no such job")
                return self._send(200, json.dumps({"status": job.status, "scan_id": job.scan_id,
                                                   "error": job.error}), "application/json")
            if path.startswith("/download/"):
                sid = path[len("/download/"):]
                return self._send(200, json.dumps(history.load(sid), indent=2), "application/json",
                                  {"Content-Disposition": f'attachment; filename="aiterprise-{sid}.json"'})
        except KeyError:
            return self._page("Not found", "<h1>Not found</h1><p>That scan is not in the local history.</p>",
                              status=404)
        return self._page("Not found", "<h1>Not found</h1>", status=404)

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._plain(403, "forbidden host")
        if not self._authed():
            return self._plain(401, "not authorised")
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{self.server.port}", f"http://localhost:{self.server.port}"):
            return self._plain(403, "cross-origin request refused")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            return self._plain(413, "request too large")
        form = {k: v[-1] for k, v in parse_qs(self.rfile.read(length).decode("utf-8", "replace")).items()}
        if not hmac.compare_digest(form.get("csrf", "").encode(), self.server.csrf.encode()):
            return self._plain(403, "missing or wrong CSRF token")
        route = urlsplit(self.path).path
        handler = {"/scan": self.post_scan, "/suppress": self.post_suppress, "/delete": self.post_delete,
                   "/login": self.post_login, "/logout": self.post_logout,
                   "/defs/update": self.post_defs_update}.get(route)
        if handler is None:
            return self._plain(404, "no such action")
        return handler(form)

    # pages --------------------------------------------------------------------------------
    def page_index(self) -> None:
        scans = history.list_scans()
        rows = []
        for s in scans:
            prev = history.previous_of(s["id"])
            diff = f' · <a href="/diff?a={quote(prev)}&b={quote(s["id"])}">diff vs previous</a>' if prev else ""
            outcome = {0: '<span class="okc">pass</span>', 1: '<span class="high">policy failure</span>',
                       2: '<span class="medium">incomplete</span>'}.get(s.get("exit_code"), _e(s.get("exit_code")))
            rows.append(
                f'<tr><td><a href="/scan/{quote(s["id"])}">{_e(s.get("project"))}</a>'
                f'<div class="small"><code>{_e(s.get("target"))}</code></div></td>'
                f'<td class="hide">{_e((s.get("started_at") or "")[:19].replace("T", " "))}</td>'
                f'<td>{s.get("components", 0)} <span class="small">({s.get("ai_components", 0)} AI)</span></td>'
                f'<td>{_sev_chips(s.get("severity") or {})}</td><td>{outcome}</td>'
                f'<td class="small"><a href="/download/{quote(s["id"])}">json</a>{diff} · '
                f'<form class="inline" method="post" action="/delete">{self._csrf_field()}'
                f'<input type="hidden" name="scan" value="{_e(s["id"])}">'
                f'<button class="ghost" title="Remove from local history">delete</button></form></td></tr>')
        running = "".join(f'<div class="notice">Scanning <code>{_e(j.path)}</code> since {j.started} — '
                          f'<a href="/jobs/{j.id}">progress</a></div>'
                          for j in self.server.jobs.values() if j.status == "running")
        table = ("<div class=\"wrap\"><table><tr><th>Project</th><th class=\"hide\">Started (UTC)</th>"
                 "<th>Components</th><th>Active findings</th><th>Result</th><th></th></tr>"
                 + "".join(rows) + "</table></div>") if rows else (
            '<p class="meta">No scans yet. Run one above, or run <code>aiterprise-scan scan --save</code>.</p>')
        body = (f'<h1>Scans</h1><div class="meta">History kept on this machine in '
                f'<code>{_e(history.history_dir())}</code>. Nothing is uploaded from this page.</div>'
                f'<h2>New scan</h2><form method="post" action="/scan" class="bar">{self._csrf_field()}'
                f'<input type="text" name="path" aria-label="Path to scan" '
                f'placeholder="C:\\path\\to\\repo or /path/to/repo" size="48" required>'
                f'<input type="checkbox" id="opt-offline" name="offline" value="1">'
                f'<label for="opt-offline">offline</label>'
                f'<input type="checkbox" id="opt-noreg" name="noregistry" value="1">'
                f'<label for="opt-noreg">no registry lookups</label>'
                f'<button>Scan</button></form>{running}<h2>History</h2>{table}')
        self._page("Scans", body, "scans")

    def page_job(self, job_id: str) -> None:
        job = self.server.jobs.get(job_id)
        if job is None:
            return self._page("Not found", "<h1>No such job</h1>", status=404)
        if job.status == "done" and job.scan_id:
            return self._redirect(f"/scan/{quote(job.scan_id)}")
        if job.status == "error":
            return self._page("Scan failed", f'<h1>Scan failed</h1><div class="notice err">{_e(job.error)}</div>'
                                             f'<p><a href="/">Back</a></p>')
        self._extra_script = (
            '<script nonce="{nonce}">(function(){var u="/api/jobs/' + job.id + '";function t(){fetch(u,'
            '{credentials:"same-origin"}).then(function(r){return r.json()}).then(function(j){if(j.status!=="running")'
            '{location.reload()}else{setTimeout(t,1000)}}).catch(function(){setTimeout(t,2000)})}t()})();</script>')
        self._page("Scanning", f'<h1>Scanning…</h1><p class="meta"><code>{_e(job.path)}</code> · started '
                               f'{job.started} UTC. This page refreshes when the scan finishes.</p>')

    def page_scan(self, sid: str, q: dict) -> None:
        doc = history.load(sid)
        tab = q.get("tab", "findings")
        s = doc.get("summary") or {}
        sev = s.get("severity") or {}
        tiles = (f'<div class="tiles"><div class="tile"><b>{s.get("components", 0)}</b>components</div>'
                 f'<div class="tile"><b>{s.get("ai_components", 0)}</b>AI components</div>'
                 + "".join(f'<div class="tile"><b class="{x}">{sev.get(x, 0)}</b>{x}</div>' for x in SEVERITIES)
                 + "</div>")
        prev = history.previous_of(sid)
        head = (f'<h1>{_e(reportdoc.project_name(doc))}</h1><div class="meta"><code>{_e(doc.get("target"))}</code> · '
                f'{_e(doc.get("started_at"))} · mode {_e(doc.get("mode"))} · exit {_e(doc.get("exit_code"))} · '
                f'{_e(doc.get("tool"))} {_e(doc.get("version"))} · <a href="/download/{quote(sid)}">json</a>'
                + (f' · <a href="/diff?a={quote(prev)}&b={quote(sid)}">diff vs previous</a>' if prev else "")
                + "</div>" + tiles)
        tabs = "".join(f'<a href="/scan/{quote(sid)}?tab={k}" class="{"on" if k == tab else ""}">{label}</a>'
                       for k, label in (("findings", f"Findings ({len(doc.get('findings') or [])})"),
                                        ("inventory", f"Inventory ({len(doc.get('components') or [])})"),
                                        ("coverage", "Coverage"), ("notes", "Notes & notices")))
        body = head + f'<div class="tabs">{tabs}</div>'
        if tab == "inventory":
            body += self._inventory(doc, q)
        elif tab == "coverage":
            body += self._coverage(doc)
        elif tab == "notes":
            body += self._notes(doc)
        else:
            body += self._findings(sid, doc, q)
        self._page(reportdoc.project_name(doc), body, "scans")

    def _findings(self, sid: str, doc: dict, q: dict) -> str:
        findings = doc.get("findings") or []
        want_sev, want_ver = q.get("severity", ""), q.get("verdict", "")
        want_status, text = q.get("status", "active"), q.get("q", "").strip().lower()

        def keep(f: dict) -> bool:
            if want_sev and f.get("severity") != want_sev:
                return False
            if want_ver and f.get("verdict") != want_ver:
                return False
            if want_status == "active" and f.get("status") not in ("new", "existing", None):
                return False
            if want_status not in ("", "active", "all") and f.get("status") != want_status:
                return False
            if text:
                hay = " ".join(str(f.get(k) or "") for k in ("title", "rule_id", "location", "advisory_id"))
                hay += " " + str((f.get("component") or {}).get("name") or "")
                if text not in hay.lower():
                    return False
            return True

        def options(name: str, values, current: str, blank: str) -> str:
            opts = [f'<option value="">{blank}</option>'] + [
                f'<option value="{v}"{" selected" if v == current else ""}>{v}</option>' for v in values]
            return f'<select name="{name}">{"".join(opts)}</select>'

        status_opts = "".join(f'<option value="{v}"{" selected" if v == want_status else ""}>{label}</option>'
                              for v, label in (("active", "active"), ("all", "all"), ("suppressed", "suppressed"),
                                               ("baselined", "baselined"), ("withdrawn", "withdrawn")))
        filters = (f'<form class="bar" method="get" action="/scan/{quote(sid)}">'
                   f'{options("severity", SEVERITIES, want_sev, "any severity")}'
                   f'{options("verdict", VERDICTS, want_ver, "any verdict")}'
                   f'<select name="status">{status_opts}</select>'
                   f'<input type="text" name="q" value="{_e(q.get("q", ""))}" placeholder="search title, rule, package">'
                   f'<button class="ghost">Filter</button></form>')
        shown = [f for f in findings if keep(f)]
        rows = []
        default_until = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        for f in shown:
            comp = f.get("component") or {}
            comp_txt = (comp.get("name") or "") + (f"@{comp['version']}" if comp.get("version") else "")
            ex = f.get("examined") or {}
            ex_txt = (f'{ex.get("sources", 0)} source(s) consulted, {ex.get("with_data", 0)} with data'
                      + (f'; skipped: {", ".join(map(str, ex.get("skipped") or []))}' if ex.get("skipped") else ""))
            q_txt = quality_text(f.get("quality"))
            protected = f.get("verdict") == "malicious"
            suppress = ""
            if f.get("status") in ("new", "existing", None):
                warn = ('<div class="notice err small">Known-malicious. Accept it only after review: this names its '
                        'fingerprint and expires.</div>' if protected else "")
                suppress = (f'<details><summary>Suppress with expiry</summary><div class="box">{warn}'
                            f'<form method="post" action="/suppress" class="bar">{self._csrf_field()}'
                            f'<input type="hidden" name="scan" value="{_e(sid)}">'
                            f'<input type="hidden" name="fingerprint" value="{_e(f.get("fingerprint"))}">'
                            f'<label>until <input type="date" name="until" value="{default_until}" required></label>'
                            f'<input type="text" name="reason" placeholder="reason (required)" size="32" required>'
                            f'<input type="text" name="approved_by" placeholder="approved by" size="16">'
                            f'<button>Suppress</button></form><div class="small">Written to '
                            f'<code>.aiterprise/suppressions.json</code> in the project; commit it so CI applies it.'
                            f'</div></div></details>')
            elif f.get("suppression"):
                sup = f["suppression"]
                suppress = (f'<div class="small">{_e(f.get("status"))}: {_e(sup.get("reason"))}'
                            + (f' · until {_e(sup.get("until"))}' if sup.get("until") else "") + "</div>")
            detail = {k: f.get(k) for k in ("evidence", "maps_to", "advisory_id", "kev") if f.get(k)}
            rows.append(
                f'<tr><td class="sev {_e(f.get("severity"))}">{_e(f.get("severity"))}</td>'
                f'<td><b>{_e(f.get("title"))}</b><div class="small"><code>{_e(f.get("rule_id"))}</code> · '
                f'{_e(f.get("verdict"))} · confidence {_e(f.get("confidence"))} · status {_e(f.get("status"))}</div>'
                f'<details><summary>Details</summary><div class="box">'
                + (f'<p><b>Fix:</b> {_e(f.get("remediation"))}</p>' if f.get("remediation") else "")
                + f'<div class="small">Fingerprint <code>{_e(f.get("fingerprint"))}</code> · {_e(ex_txt)} · '
                  f'{_e(q_txt)}</div><pre>{_e(json.dumps(detail, indent=2, ensure_ascii=False))}</pre>'
                  f'</div></details>{suppress}</td>'
                f'<td class="hide"><code>{_e(comp_txt)}</code></td>'
                f'<td class="hide"><code>{_e(f.get("location"))}</code></td></tr>')
        table = ('<div class="wrap"><table><tr><th>Severity</th><th>Finding</th><th class="hide">Component</th>'
                 '<th class="hide">Location</th></tr>' + "".join(rows) + "</table></div>") if rows else (
            '<p class="meta">No findings match these filters.</p>')
        return filters + f'<div class="small">{len(shown)} of {len(findings)} finding(s)</div>' + table

    def _inventory(self, doc: dict, q: dict) -> str:
        comps = doc.get("components") or []
        only_ai = q.get("ai") == "1"
        rows = []
        for c in sorted(comps, key=lambda c: (str(c.get("type")), str(c.get("name")))):
            if only_ai and not c.get("ai"):
                continue
            locs = c.get("locations") or []
            rows.append(f'<tr><td>{_e(c.get("type"))}</td><td><code>{_e(c.get("name"))}</code>'
                        + (' <span class="chip">AI</span>' if c.get("ai") else "") + "</td>"
                        f'<td><code>{_e(c.get("version") or c.get("version_spec") or "")}</code></td>'
                        f'<td class="hide">{_e(c.get("licence") or "")}</td>'
                        f'<td class="hide small"><code>{_e(locs[0] if locs else "")}</code>'
                        + (f" +{len(locs) - 1}" if len(locs) > 1 else "") + "</td></tr>")
        toggle = (f'<div class="bar"><a href="?tab=inventory{"" if only_ai else "&ai=1"}">'
                  f'{"show all components" if only_ai else "AI components only"}</a></div>')
        return toggle + ('<div class="wrap"><table><tr><th>Type</th><th>Name</th><th>Version</th>'
                         '<th class="hide">Licence</th><th class="hide">Where</th></tr>' + "".join(rows)
                         + "</table></div>")

    def _coverage(self, doc: dict) -> str:
        rows = []
        for src, ex in sorted((doc.get("examined") or {}).items()):
            if ex.get("errors"):
                state = f'<span class="high">{_e(ex["errors"])} error(s): UNVERIFIED</span>'
            elif ex.get("skipped"):
                state = f'<span class="medium">skipped: {_e(ex["skipped"])}</span>'
            else:
                state = '<span class="okc">ok</span>'
            rows.append(f'<tr><td><code>{_e(src)}</code></td><td>{_e(ex.get("checked", 0))}</td>'
                        f'<td>{_e(ex.get("with_data", 0))}</td><td>{state}</td></tr>')
        return ('<p class="meta">"No match" is not "never checked": each source lists how many items it judged and '
                'how many had data. A skipped or failing source means those items are UNVERIFIED, not safe.</p>'
                '<div class="wrap"><table><tr><th>Source</th><th>Checked</th><th>With data</th><th>State</th></tr>'
                + "".join(rows) + "</table></div>")

    def _notes(self, doc: dict) -> str:
        notes = "".join(f"<li>{_e(n)}</li>" for n in doc.get("notes") or []) or "<li class=\"meta\">none</li>"
        notices = "".join(f'<li>{_e(n.get("text"))}' + (f' &lt;{_e(n["url"])}&gt;' if n.get("url") else "")
                          + "</li>" for n in doc.get("notices") or []) or "<li class=\"meta\">none</li>"
        return f"<h2>Notes</h2><ul>{notes}</ul><h2>Data notices</h2><ul>{notices}</ul>"

    def page_diff(self, q: dict) -> None:
        scans = history.list_scans()
        a, b = q.get("a", ""), q.get("b", "")

        def select(name: str, current: str) -> str:
            opts = "".join(f'<option value="{_e(s["id"])}"{" selected" if s["id"] == current else ""}>'
                           f'{_e(s.get("project"))} · {_e((s.get("started_at") or "")[:16].replace("T", " "))}</option>'
                           for s in scans)
            return f'<select name="{name}">{opts}</select>'

        body = (f'<h1>Diff</h1><form class="bar" method="get" action="/diff">from {select("a", a)} to '
                f'{select("b", b)} <button class="ghost">Compare</button></form>')
        if a and b:
            old, new = history.load(a), history.load(b)
            d = history.diff(old, new)

            def table(items: list[dict]) -> str:
                if not items:
                    return '<p class="meta">none</p>'
                return ('<div class="wrap"><table>' + "".join(
                    f'<tr><td class="sev {_e(f.get("severity"))}">{_e(f.get("severity"))}</td>'
                    f'<td>{_e(f.get("title"))}<div class="small"><code>{_e(f.get("rule_id"))}</code></div></td>'
                    f'<td class="hide"><code>{_e(f.get("location"))}</code></td></tr>' for f in items)
                    + "</table></div>")

            body += (f'<div class="tiles"><div class="tile"><b class="high">{len(d["new"])}</b> new</div>'
                     f'<div class="tile"><b class="okc">{len(d["fixed"])}</b> fixed</div>'
                     f'<div class="tile"><b>{len(d["unchanged"])}</b> unchanged</div>'
                     f'<div class="tile"><b>{len(d["components_added"])}</b> components added</div>'
                     f'<div class="tile"><b>{len(d["components_removed"])}</b> removed</div></div>'
                     f'<h2>New findings</h2>{table(d["new"])}<h2>Fixed (gone since the earlier scan)</h2>'
                     f'{table(d["fixed"])}<div class="grid"><div><h2>Components added</h2><ul>'
                     + "".join(f"<li><code>{_e(c)}</code></li>" for c in d["components_added"])
                     + '</ul></div><div><h2>Components removed</h2><ul>'
                     + "".join(f"<li><code>{_e(c)}</code></li>" for c in d["components_removed"]) + "</ul></div></div>")
        elif len(scans) < 2:
            body += '<p class="meta">Two scans are needed to compare.</p>'
        self._page("Diff", body, "diff")

    def page_account(self) -> None:
        from . import bundles

        cred = credentials.load()
        if cred is None:
            acct = (f'<p><b>Not logged in.</b> SecDB judgements (known-bad hashes, package and MCP reputation) are '
                    f'off. A free key works; batching and scan uploads need a paid plan.</p>'
                    f'<form method="post" action="/login" class="bar">{self._csrf_field()}'
                    f'<input type="password" name="key" placeholder="aik_live_…" size="44" autocomplete="off" required>'
                    f'<button>Log in</button></form><div class="small">The key is checked with SecDB '
                    f'<code>GET /v1/me</code>, then stored in <code>{_e(credentials.home())}</code>'
                    f'{" (DPAPI-encrypted)" if sys.platform == "win32" else " (mode 0600)"}.</div>')
        else:
            acct = (f'<p>Credential <code>{_e(cred.masked)}</code> · {_e(cred.kind)} · '
                    f'{"from the environment" if cred.origin == "env" else "stored"}</p>')
            client = secdb.Client(cred)
            try:
                me = client.me()
                limits = me.get("limits") or {}
                acct += (f'<div class="tiles"><div class="tile"><b>{_e(me.get("plan"))}</b>plan</div>'
                         + "".join(f'<div class="tile"><b>{_e(v)}</b>{_e(k.replace("_", " "))}</div>'
                                   for k, v in limits.items() if v is not None) + "</div>")
                try:
                    usage = client.usage()
                    acct += "<table><tr><th>Meter</th><th>Used</th><th>Included</th><th>Hard stop</th></tr>" + "".join(
                        f'<tr><td>{_e(m.get("meter"))}</td><td>{_e(m.get("used"))}</td><td>{_e(m.get("included"))}'
                        f'</td><td>{_e(m.get("ceiling"))}</td></tr>' for m in usage.get("meters") or []) + "</table>"
                except secdb.SecDBError as err:
                    acct += f'<p class="small">Usage unavailable: {_e(err)}</p>'
            except secdb.SecDBError as err:
                acct += f'<div class="notice err">{_e(err)}</div>'
            if cred.origin != "env":
                acct += (f'<form method="post" action="/logout" class="bar">{self._csrf_field()}'
                         f'<button class="danger">Log out</button></form>')
        try:
            act = bundles.active()
            defs = (f'<p>Active bundle <code>{_e(act[0])}</code> · {_e(act[1].get("channel"))} · created '
                    f'{_e(act[1].get("created_at"))}</p>' if act else
                    '<p>No signed bundle installed: the definitions shipped with this version are in use.</p>')
        except bundles.BundleError as err:  # a pin (AITERPRISE_DEFS) that cannot be honoured
            defs = f'<div class="notice err">{_e(err)}</div>'
        defs += (f'<form method="post" action="/defs/update" class="bar">{self._csrf_field()}'
                 f'<button class="ghost">Check SecDB for a newer bundle</button></form>')
        self._page("Account", f"<h1>Account</h1><h2>SecDB</h2>{acct}<h2>Definitions</h2>{defs}", "account")

    # actions ------------------------------------------------------------------------------
    def post_scan(self, form: dict) -> None:
        raw = form.get("path", "").strip().strip('"')
        path = Path(raw).expanduser()
        if not raw or not path.exists():
            self.server.flash.append(("err", f"Not found: {raw or '(empty)'}"))
            return self._redirect("/")
        job = _start_job(self.server, path.resolve(), form.get("offline") == "1", form.get("noregistry") != "1")
        self._redirect(f"/jobs/{job.id}")

    def post_suppress(self, form: dict) -> None:
        sid = form.get("scan", "")
        try:
            doc = history.load(sid)
        except KeyError:
            return self._page("Not found", "<h1>Not found</h1>", status=404)
        fp = form.get("fingerprint", "")
        if not any(f.get("fingerprint") == fp for f in doc.get("findings") or []):
            return self._page("Not found", "<h1>That finding is not in this scan</h1>", status=404)
        target = Path(str(doc.get("target") or ""))
        if not target.exists():
            return self._page("Cannot suppress", f'<div class="notice err">The scanned path '
                                                 f'<code>{_e(target)}</code> is not on this machine.</div>', status=400)
        try:
            written = policy_mod.add_local_suppression(target, fp, form.get("until", ""), form.get("reason", ""),
                                                       form.get("approved_by"))
        except ValueError as err:
            return self._page("Cannot suppress", f'<h1>Cannot suppress</h1><div class="notice err">{_e(err)}</div>'
                                                 f'<p><a href="/scan/{quote(sid)}">Back</a></p>', status=400)
        self.server.flash.append(("okb", f"Suppressed {fp} until {form.get('until')}; written to {written}. "
                                         "Re-scan to see it applied."))
        self._redirect(f"/scan/{quote(sid)}")

    def post_delete(self, form: dict) -> None:
        try:
            history.load(form.get("scan", ""))
            history.delete(form["scan"])
        except KeyError:
            pass
        self._redirect("/")

    def post_login(self, form: dict) -> None:
        key = form.get("key", "").strip()
        if not key.startswith("aik_"):
            self.server.flash.append(("err", "That is not a SecDB API key (they start with aik_)."))
            return self._redirect("/account")
        try:
            me = secdb.Client(credentials.Credential("api_key", key, "ui")).me()
        except secdb.SecDBError as err:
            self.server.flash.append(("err", f"{err} — key not saved"))
            return self._redirect("/account")
        credentials.save_api_key(key)
        self.server.flash.append(("okb", f"Logged in · plan {me.get('plan')} · key {credentials.mask(key)}"))
        self._redirect("/account")

    def post_logout(self, form: dict) -> None:
        credentials.clear()
        self.server.flash.append(("okb", "SecDB credentials removed from this machine."))
        self._redirect("/account")

    def post_defs_update(self, form: dict) -> None:
        from . import defscli

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = defscli.cmd_update(argparse.Namespace(root_key=None, channel=None, signing_keys=None))
        msg = (out.getvalue() + err.getvalue()).strip().replace(f"{TOOL_NAME}: error: ", "")
        self.server.flash.append(("okb" if code == 0 else "err", msg or "done"))
        self._redirect("/account")


def serve(port: int = 0, open_browser: bool = True) -> int:
    try:
        server = make_server(port)
    except OSError as err:
        print(f"{TOOL_NAME}: error: cannot listen on 127.0.0.1:{port}: {err}", file=sys.stderr)
        return 2
    url = f"http://127.0.0.1:{server.port}/?token={server.token}"
    print(f"AIterprise AIBOM UI on http://127.0.0.1:{server.port}/ (local only; Ctrl+C stops it)")
    print(f"open: {url}")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - no browser is fine
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
