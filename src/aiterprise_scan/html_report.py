"""Self-contained HTML report (C07, flat MVP). No scripts, no external assets.

Everything shown comes from scanned, untrusted content (package names, MCP descriptions, model
metadata), so every value is HTML-escaped and nothing is rendered as markup.
"""

from __future__ import annotations

from collections import Counter
from html import escape

from . import TOOL_NAME, __version__
from .model import SEVERITIES, ScanResult, sort_findings
from .reportdoc import summary

_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#e3e6ea;--card:#f6f8fa;
--critical:#b3261e;--high:#d1490b;--medium:#a86b00;--low:#2f6db5;--info:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--fg:#e6e8eb;--muted:#9aa3ad;--line:#2a2f36;
--card:#191d22;--critical:#ff6b61;--high:#ff8a4c;--medium:#e0b341;--low:#6ea8ff;--info:#9aa3ad}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}
.meta{color:var(--muted);font-size:13px}
.tiles{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:96px}
.tile b{display:block;font-size:20px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.sev{font-weight:700;text-transform:uppercase;font-size:12px;white-space:nowrap}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}
.low{color:var(--low)}.info{color:var(--info)}
code{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
.small{color:var(--muted);font-size:12px}.wrap{overflow-x:auto}
"""


def _e(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def render(result: ScanResult) -> str:
    s = summary(result)
    counts = s["severity"]
    out: list[str] = []
    a = out.append
    a("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    a("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    a(f"<title>AI-BOM scan report</title><style>{_CSS}</style></head><body><main>")
    a(f"<h1>AI-BOM scan report</h1><div class=\"meta\">{_e(TOOL_NAME)} {_e(__version__)} · "
      f"target <code>{_e(result.target)}</code> · mode {_e(result.mode)} · {_e(result.started_at)} · "
      f"exit {result.exit_code}</div>")
    a("<div class=\"tiles\">")
    a(f"<div class=\"tile\"><b>{s['components']}</b>components</div>")
    a(f"<div class=\"tile\"><b>{s['ai_components']}</b>AI components</div>")
    for sev in SEVERITIES:
        a(f"<div class=\"tile\"><b class=\"{sev}\">{counts[sev]}</b>{sev}</div>")
    a("</div>")

    a("<h2>Sources examined</h2><p class=\"small\">“No match” is not “never checked”: "
      "with data / checked per source.</p><div class=\"wrap\"><table><tr><th>Source</th>"
      "<th>With data</th><th>Checked</th><th>Notes</th></tr>")
    for name, ex in sorted(result.examined.items()):
        note = ex.skipped or ""
        if ex.errors:
            note = f"{note} {ex.errors} error(s)".strip()
        a(f"<tr><td>{_e(name)}</td><td>{ex.with_data}</td><td>{ex.checked}</td><td>{_e(note)}</td></tr>")
    a("</table></div>")

    a("<h2>Findings</h2><div class=\"wrap\"><table><tr><th>Severity</th><th>Finding</th>"
      "<th>Component</th><th>Evidence</th><th>Status</th></tr>")
    for f in sort_findings(result.findings):
        ev = "<br>".join(
            f"{_e(e.source)} {_e(e.record or '')}" for e in f.evidence[:4]
        )
        loc = f"<div class=\"small\">at <code>{_e(f.location)}</code></div>" if f.location else ""
        fix = f"<div class=\"small\">fix: {_e(f.remediation)}</div>" if f.remediation else ""
        comp = _e(f.component.display) if f.component else ""
        a(f"<tr><td class=\"sev {f.severity}\">{_e(f.severity)}</td><td>{_e(f.title)}{loc}{fix}"
          f"<div class=\"small\"><code>{_e(f.rule_id)}</code> · {_e(f.fingerprint)}</div></td>"
          f"<td><code>{comp}</code></td><td>{ev}</td><td>{_e(f.status)}</td></tr>")
    if not result.findings:
        a("<tr><td colspan=\"5\">No findings.</td></tr>")
    a("</table></div>")

    by_type = Counter(c.ctype for c in result.components)
    a("<h2>Inventory</h2><p class=\"small\">"
      + " · ".join(f"{n} {_e(t)}" for t, n in sorted(by_type.items())) + "</p>")
    a("<div class=\"wrap\"><table><tr><th>Type</th><th>Component</th><th>Licence</th><th>Found at</th></tr>")
    for c in sorted(result.components, key=lambda c: (c.ctype, c.display)):
        where = "<br>".join(f"<code>{_e(loc)}</code>" for loc in c.locations[:3])
        spec = f" <span class=\"small\">[{_e(c.version_spec)}]</span>" if c.version_spec and not c.version else ""
        a(f"<tr><td>{_e(c.ctype)}{' · AI' if c.ai else ''}</td><td><code>{_e(c.display)}</code>{spec}</td>"
          f"<td>{_e(c.licence or '')}</td><td>{where}</td></tr>")
    a("</table></div>")

    if result.notes:
        a("<h2>Notes</h2><ul>" + "".join(f"<li>{_e(n)}</li>" for n in result.notes) + "</ul>")
    if result.notices:
        a("<h2>Data notices</h2><ul>" + "".join(
            f"<li>{_e(n.get('text', ''))}" + (f" &lt;{_e(n['url'])}&gt;" if n.get("url") else "") + "</li>"
            for n in result.notices) + "</ul>")
    a("<p class=\"small\">Licence verdicts are advisory and are not legal advice.</p>")
    a("</main></body></html>\n")
    return "".join(out)
