"""Editor tasks and the GitLab CI template (design doc 13 C45 task templates, S3 GitLab template),
and the two report formats they rely on: `compact` (one line per new finding, for problem matchers
and quickfix lists) and `codequality` (GitLab's merge-request widget).
"""

from __future__ import annotations

import json
import re
import shlex
import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import cli, miniyaml, report
from aiterprise_scan.model import Component, Finding, Location, ScanResult

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "templates" / "vscode" / "tasks.json"
GITLAB = ROOT / "templates" / "gitlab" / "aiterprise-scan.gitlab-ci.yml"


def finding(title, severity="high", rule="ait.pkg.malicious", path="requirements.txt", line=3, status="new"):
    comp = Component(name="litellm", version="1.82.7", ecosystem="pypi",
                     locations=[Location(path, line)] if path else [], ai=True)
    f = Finding(rule, title, severity, "malicious", 90, comp)
    f.status = status
    return f


def result(findings, exit_code=1):
    return ScanResult(target="demo", mode="offline", components=[f.component for f in findings],
                      findings=findings, exit_code=exit_code)


def scan_planted(tmp: str, fmt: str) -> tuple[int, str]:
    root = Path(tmp) / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("litellm==1.82.7\n", encoding="utf-8")
    out = Path(tmp) / "out"
    code = cli.main(["scan", str(root), "--offline", "--format", fmt, "--out", str(out)])
    name = {"compact": "report.compact.txt", "codequality": "codequality.json"}[fmt]
    return code, (out / name).read_text(encoding="utf-8")


class CompactFormatTest(unittest.TestCase):
    def test_one_line_per_new_finding(self):
        text = report.render_compact(result([
            finding("Known-malicious package version (litellm 1.82.7)", "critical"),
            finding("Typosquat of requests", "medium", "ait.pkg.typosquat", "pyproject.toml", 8),
            finding("Info note", "info", "ait.licence.obligations", "app.py", None),
            finding("Baselined", status="acknowledged"),
        ]))
        self.assertEqual(text.splitlines(), [
            "requirements.txt:3: error: Known-malicious package version (litellm 1.82.7) [critical ait.pkg.malicious]",
            "pyproject.toml:8: warning: Typosquat of requests [medium ait.pkg.typosquat]",
            "app.py:1: info: Info note [info ait.licence.obligations]",
        ])

    def test_hostile_text_stays_on_one_line(self):
        text = report.render_compact(result([finding("a\nb.py:1: error: forged‮", path="x\ny.py")]))
        self.assertEqual(len(text.splitlines()), 1)
        self.assertNotIn("‮", text)

    def test_a_finding_without_a_location_is_kept(self):
        text = report.render_compact(result([finding("No file", path=None)]))
        self.assertEqual(text, ".:1: error: No file [high ait.pkg.malicious]\n")


class CodeQualityFormatTest(unittest.TestCase):
    def test_gitlab_fields(self):
        f = finding("Known-malicious package version (litellm 1.82.7)", "critical")
        doc = json.loads(report.dumps_codequality(result([f, finding("Gone", status="suppressed")])))
        self.assertEqual(doc, [{
            "description": "Known-malicious package version (litellm 1.82.7)",
            "check_name": "ait.pkg.malicious",
            "fingerprint": f.fingerprint,
            "severity": "blocker",
            "location": {"path": "requirements.txt", "lines": {"begin": 3}},
        }])

    def test_severity_scale(self):
        sevs = [json.loads(report.dumps_codequality(result([finding("t", s)])))[0]["severity"]
                for s in ("critical", "high", "medium", "low", "info")]
        self.assertEqual(sevs, ["blocker", "critical", "major", "minor", "info"])


class VsCodeTasksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = json.loads(TASKS.read_text(encoding="utf-8"))

    def test_every_task_runs_a_command_the_cli_accepts(self):
        self.assertEqual(self.doc["version"], "2.0.0")
        parser = cli.build_parser()
        labels = []
        for task in self.doc["tasks"]:
            labels.append(task["label"])
            self.assertEqual(task["command"], "aiterprise-scan")
            args = [a.replace("${workspaceFolder}", "/w") for a in task["args"]]
            parser.parse_args(args)  # SystemExit on anything it refuses
        self.assertGreaterEqual(len(labels), 3)

    def test_the_problem_matcher_reads_a_real_scan(self):
        task = next(t for t in self.doc["tasks"] if "compact" in t["args"])
        matcher = task["problemMatcher"]
        pat = matcher["pattern"]
        rx = re.compile(pat["regexp"])
        with tempfile.TemporaryDirectory() as tmp:
            code, text = scan_planted(tmp, "compact")
        self.assertEqual(code, 1)
        lines = text.splitlines()
        self.assertTrue(lines)
        for ln in lines:
            m = rx.match(ln)
            self.assertIsNotNone(m, ln)
            self.assertIn(m.group(pat["severity"]), ("error", "warning", "info"))
        first = rx.match(lines[0])
        self.assertEqual((first.group(pat["file"]), first.group(pat["line"])), ("requirements.txt", "1"))


class GitLabTemplateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = GITLAB.read_text(encoding="utf-8")
        self.job = miniyaml.load(self.text)["aiterprise-scan"]

    def test_the_scan_line_is_one_the_cli_accepts(self):
        scan = next(ln for ln in self.job["script"] if "aiterprise-scan scan" in ln)
        cmd = scan[scan.index("aiterprise-scan scan"):].split(" ||")[0]
        variables = {k: str(v) for k, v in self.job["variables"].items()}
        argv = [re.sub(r"\$\{?(\w+)\}?", lambda m: variables.get(m.group(1), ""), a) for a in shlex.split(cmd)][1:]
        args = cli.build_parser().parse_args([a for a in argv if a])
        self.assertIn("codequality", args.format)
        self.assertEqual(args.cdx_version, "1.6")  # GitLab reads CycloneDX up to 1.6

    def test_reports_point_at_files_the_scan_writes(self):
        reports = self.job["artifacts"]["reports"]
        self.assertEqual(reports["codequality"], "aiterprise-report/codequality.json")
        self.assertEqual(reports["cyclonedx"], "aiterprise-report/aibom.cdx.json")
        self.assertEqual(self.job["artifacts"]["when"], "always")
        with tempfile.TemporaryDirectory() as tmp:
            code, text = scan_planted(tmp, "codequality")
        self.assertEqual(code, 1)
        issues = json.loads(text)
        self.assertTrue(issues)
        for issue in issues:
            self.assertEqual(set(issue), {"description", "check_name", "fingerprint", "severity", "location"})


if __name__ == "__main__":
    unittest.main()
