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


if __name__ == "__main__":
    unittest.main()
