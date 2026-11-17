"""Machine-readable output written to a redirected stdout is UTF-8 on every platform."""

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import cli


class RedirectedStdoutTests(unittest.TestCase):
    def test_json_to_a_redirected_stdout_is_utf8(self):
        # Windows gives a redirected stdout the ANSI code page (cp1252); JSON must still be UTF-8
        raw = io.BytesIO()
        stdout = io.TextIOWrapper(raw, encoding="cp1252", newline="")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "café—repo"
            target.mkdir()
            (target / "requirements.txt").write_text("openai==1.40.0\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"AITERPRISE_HOME": tmp}), mock.patch("sys.stdout", stdout), \
                    mock.patch("sys.stderr", io.StringIO()):
                cli.main(["scan", str(target), "--offline", "--format", "json"])
                stdout.flush()
        doc = json.loads(raw.getvalue().decode("utf-8"))
        self.assertTrue(doc["target"].endswith("café—repo"))


class OutPathTests(unittest.TestCase):
    """`--out` names a directory of reports, or, with one format, the report file itself."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.target = self.base / "repo"
        self.target.mkdir()
        (self.target / "requirements.txt").write_text("openai==1.40.0\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, *args):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"AITERPRISE_HOME": str(self.base / "home"),
                                          "AITERPRISE_CACHE_DIR": str(self.base / "cache")}), \
                mock.patch("sys.stdout", io.StringIO()) as out, mock.patch("sys.stderr", err):
            cli.main(["scan", str(self.target), "--offline", "--no-cache", *args])
        return out.getvalue(), err.getvalue()

    def test_one_format_and_a_report_file_name_writes_that_file(self):
        path = self.base / "results.sarif"
        out, err = self.scan("--format", "sarif", "--out", str(path))
        self.assertTrue(path.is_file())
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["version"], "2.1.0")
        self.assertEqual(out, "")
        self.assertIn(f"report written to {path}", err)

    def test_the_file_parent_is_created(self):
        path = self.base / "build" / "ai" / "aibom.json"
        self.scan("--format", "cyclonedx", "--out", str(path))
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["bomFormat"], "CycloneDX")

    def test_the_default_table_goes_to_a_txt_file(self):
        path = self.base / "scan.txt"
        out, _ = self.scan("--out", str(path))
        self.assertTrue(path.is_file())
        self.assertIn("DISCOVERY  1 files walked", path.read_text(encoding="utf-8"))
        self.assertEqual(out, "")

    def test_every_report_suffix_names_a_file(self):
        for fmt, name in [("json", "r.json"), ("html", "r.html"), ("html", "r.htm"), ("markdown", "r.md"),
                          ("compact", "r.txt"), ("codequality", "cq.JSON")]:
            path = self.base / name
            self.scan("--format", fmt, "--out", str(path))
            self.assertTrue(path.is_file(), name)

    def test_a_directory_name_still_gets_the_named_reports(self):
        for name in ("reports", "build/v1.2"):  # no suffix, or one that is no report's
            out_dir = self.base / name
            self.scan("--format", "json", "--out", str(out_dir))
            self.assertTrue((out_dir / "report.json").is_file(), name)

    def test_several_formats_always_mean_a_directory(self):
        out_dir = self.base / "reports.json"
        _, err = self.scan("--format", "json", "--format", "sarif", "--out", str(out_dir))
        self.assertTrue((out_dir / "report.json").is_file())
        self.assertTrue((out_dir / "report.sarif").is_file())
        self.assertIn(f"reports written to {out_dir}", err)

    def test_an_existing_directory_is_never_replaced_by_a_file(self):
        out_dir = self.base / "old.json"
        out_dir.mkdir()
        self.scan("--format", "json", "--out", str(out_dir))
        self.assertTrue((out_dir / "report.json").is_file())


if __name__ == "__main__":
    unittest.main()
