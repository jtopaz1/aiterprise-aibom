#!/usr/bin/env python3
"""Draw the README's picture: one offline scan of the killer demo, as a terminal window (SVG).

    python tools/render_demo.py [--out docs/assets/killer-demo.svg]

It builds the killer-demo repository (tools/killer_demo.py), scans it offline with the definitions
bundled in this checkout, and keeps the report's header and the first finding of each of the five
planted problems. Run it again after a change to the table report or to the bundled data; nothing
checks that the picture is current, only that it shows the five problems.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import killer_demo  # noqa: E402

from aiterprise_scan import cli  # noqa: E402

OUT = ROOT / "docs" / "assets" / "killer-demo.svg"
WIDTH = 116  # characters per line; longer lines end in an ellipsis
CHAR_W, LINE_H, FONT, PAD, BAR = 7.8, 18, 13, 16, 30
BG, FG, DIM, PROMPT = "#0d1117", "#e6edf3", "#8b949e", "#3fb950"
COLOURS = {"CRITICAL": "#ff6b6b", "HIGH": "#f0a030", "MEDIUM": "#d8c25a", "LOW": "#6cb6ff", "INFO": "#8b949e"}

_BLOCK = re.compile(r"^ (CRITICAL|HIGH|MEDIUM|LOW|INFO) ")
_RULE = re.compile(r"\brule: (\S+)")
PICKS = (
    ("MCP tool-description poisoning", lambda rule, head: rule.startswith("ait.mcp.desc.")),
    ("unsafe pickle in model.pt", lambda rule, head: rule == "ait.model.pickle.dangerous-global"),
    ("malicious litellm 1.82.7", lambda rule, head: rule == "ait.pkg.malicious"),
    ("transformers 4.44.0 known CVE", lambda rule, head: rule.startswith("ait.vuln.") and "transformers" in head),
    ("Llama 3 conditional licence", lambda rule, head: rule == "ait.licence.conditional"),
)


def excerpt(table: str, code: int | None = None) -> list[str]:
    """The command, the report header, and the first finding block of each planted problem."""
    lines = table.splitlines()
    first = next((i for i, ln in enumerate(lines) if _BLOCK.match(ln)), len(lines))
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for ln in lines[first:]:
        if _BLOCK.match(ln):
            current = [ln]
            blocks.append(current)
        elif current is not None and ln.startswith("           "):
            current.append(ln)
        else:
            current = None
    chosen = []
    for label, test in PICKS:
        hit = next((b for b in blocks
                    if test(next((m.group(1) for m in map(_RULE.search, b) if m), ""), b[0])), None)
        if hit is None:
            raise ValueError(f"the report has no finding for {label}")
        chosen.append(hit)
    m = re.search(r"JUDGEMENT\s+(\d+) findings", table)
    total = int(m.group(1)) if m else len(blocks)
    out = ["$ aiterprise-scan . --offline", *lines[:first]]
    for b in sorted(chosen, key=lambda b: blocks.index(b)):
        out += b
    tail = f" … {total - len(chosen)} more findings in the full report"
    if code is not None:
        tail += f" · exit {code}" + (": the gate fails (--fail-on high)" if code == 1 else "")
    return out + ["", tail]


def _clip(line: str) -> str:
    return line if len(line) <= WIDTH else line[:WIDTH - 1] + "…"


def render_svg(lines: list[str], title: str) -> str:
    rows = [_clip(ln.rstrip()) for ln in lines]
    w = int(PAD * 2 + CHAR_W * WIDTH)
    h = int(BAR + PAD + LINE_H * len(rows))
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
           f'role="img" aria-label="{escape(title)}">',
           f"<title>{escape(title)}</title>",
           f'<rect width="{w}" height="{h}" rx="8" fill="{BG}"/>',
           '<circle cx="18" cy="15" r="5" fill="#ff5f56"/><circle cx="34" cy="15" r="5" fill="#ffbd2e"/>'
           '<circle cx="50" cy="15" r="5" fill="#27c93f"/>',
           f'<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="{FONT}" '
           f'fill="{FG}">']
    y = BAR + LINE_H - 4
    for line in rows:
        m = _BLOCK.match(line)
        if m:
            tag = m.group(1)
            rest = line[m.end(1):]
            out.append(f'<text x="{PAD}" y="{y}" xml:space="preserve"> <tspan fill="{COLOURS[tag]}" font-weight="bold">{tag}</tspan>'
                       f"{escape(rest)}</text>")
        elif line.startswith("$ "):
            out.append(f'<text x="{PAD}" y="{y}" xml:space="preserve" fill="{PROMPT}">{escape(line)}</text>')
        elif line.startswith("           ") or line.startswith(" …"):
            out.append(f'<text x="{PAD}" y="{y}" xml:space="preserve" fill="{DIM}">{escape(line)}</text>')
        else:
            out.append(f'<text x="{PAD}" y="{y}" xml:space="preserve">{escape(line)}</text>')
        y += LINE_H
    out.append("</g>")
    out.append("</svg>")
    return "\n".join(out) + "\n"


def scan_table(work: Path) -> tuple[int, str]:
    """(exit code, table report) of an offline scan of the killer demo, run from inside it."""
    repo = work / "demo-repo"
    killer_demo.build_repo(repo)
    saved_env = {k: os.environ.get(k) for k in ("AITERPRISE_DEFS", "AITERPRISE_CACHE_DIR", "AITERPRISE_API_KEY")}
    saved_cwd = os.getcwd()
    os.environ.update({"AITERPRISE_DEFS": "bundled", "AITERPRISE_CACHE_DIR": str(work / "cache")})
    os.environ.pop("AITERPRISE_API_KEY", None)
    buf = io.StringIO()
    try:
        os.chdir(repo)  # the report then names the target ".", not a path on this machine
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            code = cli.main(["scan", ".", "--offline", "--format", "table"])
    finally:
        os.chdir(saved_cwd)
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return code, buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="aiterprise-render-") as tmp:
        code, table = scan_table(Path(tmp))
    lines = excerpt(table, code)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_svg(lines, "aiterprise-scan: one offline scan of the killer demo"),
                        encoding="utf-8", newline="\n")
    print(f"wrote {args.out} ({len(lines)} lines, exit {code})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
