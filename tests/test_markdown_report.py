"""The Markdown report (`--format markdown`): what the GitHub Action posts as a pull-request comment
and writes to the job summary (design doc 13 C42).

Scanned text is hostile here too: a finding title or path that carries Markdown must not split the
table, mention a user, load an image or inject HTML in a comment that a bot posts.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import cli, report
from aiterprise_scan.model import Component, Finding, Location, ScanResult

MARKER = "<!-- aiterprise-scan report -->"


def finding(title: str, severity: str = "high", rule: str = "ait.pkg.malicious", path: str = "requirements.txt",
            line: int | None = 3, status: str = "new") -> Finding:
    comp = Component(name="litellm", version="1.82.7", ecosystem="pypi", locations=[Location(path, line)], ai=True)
    f = Finding(rule, title, severity, "malicious", 90, comp)
    f.status = status
    return f


def result(findings: list[Finding], exit_code: int = 1) -> ScanResult:
    comps = [f.component for f in findings if f.component] or [Component(name="openai", ai=True)]
    return ScanResult(target="demo", mode="offline", components=comps, findings=findings, exit_code=exit_code)


def table_rows(md: str) -> list[str]:
    return [ln for ln in md.splitlines() if ln.startswith("| ") and not ln.startswith("| Severity")]


class MarkdownReportTest(unittest.TestCase):
    def test_a_failing_scan_lists_new_findings_by_severity(self):
        md = report.render_markdown(result([
            finding("Typosquat of requests", "medium", "ait.pkg.typosquat", "pyproject.toml", 8),
            finding("Known-malicious package version (litellm 1.82.7)", "critical"),
            finding("Baselined one", "high", status="acknowledged"),
            finding("Suppressed one", "high", status="suppressed"),
        ]))
        self.assertTrue(md.startswith(MARKER + "\n"))
        self.assertIn("fails the gate", md)
        self.assertIn("**2 new findings** (1 critical, 1 medium)", md)
        self.assertIn("2 suppressed or baselined", md)
        rows = table_rows(md)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], "| critical | `Known-malicious package version (litellm 1.82.7)` "
                                  "| `requirements.txt:3` | `ait.pkg.malicious` |")
        self.assertIn("`ait.pkg.typosquat`", rows[1])
        self.assertNotIn("Baselined one", md)
        self.assertNotIn("Suppressed one", md)

    def test_a_clean_scan_says_it_passes(self):
        md = report.render_markdown(result([], exit_code=0))
        self.assertIn("passes the gate", md)
        self.assertIn("No new findings.", md)
        self.assertEqual(table_rows(md), [])

    def test_an_incomplete_scan_says_so_and_shows_the_notes(self):
        r = result([], exit_code=2)
        r.notes.append("osv: unreachable; 4 package(s) were not checked")
        md = report.render_markdown(r)
        self.assertIn("incomplete", md)
        self.assertIn("`osv: unreachable; 4 package(s) were not checked`", md)

    def test_hostile_text_stays_inert(self):
        evil = ("x | y `z` @octocat ![p](https://evil.test/p.png?d=1) <img src=x onerror=alert(1)> "
                "[click](https://evil.test) :warning:\nnext line‮")
        md = report.render_markdown(result([finding(evil, path="a|b`c/@admin.py", line=None)]))
        (row,) = table_rows(md)
        self.assertEqual(row.count("|"), 5, row)  # the four cells stay four
        cells = [c.strip() for c in row.strip("|").split("|")]
        for cell in cells[1:]:
            self.assertRegex(cell, r"^`[^`]*`$")  # every scanned string is one inline code span
        self.assertNotIn("‮", md)
        self.assertNotIn("next line", md.split("\n", 3)[-1].split(row)[0])  # no line break inside a row
        self.assertIn("@octocat", cells[1])
        outside = re.sub(r"`[^`]*`", "", md)
        for bad in ("@octocat", "@admin", "![", "<img", "](", ":warning:"):
            self.assertNotIn(bad, outside)

    def test_long_reports_are_capped(self):
        md = report.render_markdown(result([finding(f"finding {i:02d}", "low") for i in range(60)]), max_rows=50)
        self.assertEqual(len(table_rows(md)), 50)
        self.assertIn("10 more", md)
        long = report.render_markdown(result([finding("y" * 5000)]))
        self.assertLess(len(table_rows(long)[0]), 400)

    def test_the_cli_writes_report_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "requirements.txt").write_text("litellm==1.82.7\n", encoding="utf-8")
            out = Path(tmp) / "out"
            code = cli.main(["scan", str(root), "--offline", "--format", "markdown", "--out", str(out)])
            md = (out / "report.md").read_text(encoding="utf-8")
        self.assertEqual(code, 1)
        self.assertIn("fails the gate", md)
        self.assertIn("`ait.pkg.malicious`", md)


if __name__ == "__main__":
    unittest.main()
