"""The design doc 13 §3 killer demo, offline, as an acceptance test: one scan finds all five."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "killer_demo", Path(__file__).resolve().parents[1] / "tools" / "killer_demo.py")
killer_demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(killer_demo)


class KillerDemoTests(unittest.TestCase):
    def test_offline_scan_finds_all_five(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, report, hits = killer_demo.run(Path(tmp))
        missed = [label for label, found in hits.items() if not found]
        self.assertEqual(missed, [])
        self.assertEqual(code, 1)  # critical findings fail the default gate
        self.assertEqual({f["severity"] for f in hits["malicious litellm 1.82.7 (MAL-2026-2144)"]}, {"critical"})

    def test_an_external_executable_is_held_to_the_same_five(self):
        # what CI does with each PyInstaller binary; here the "binary" is this interpreter running the package
        import os
        import sys

        src = str(Path(__file__).resolve().parents[1] / "src")
        old = os.environ.get("PYTHONPATH")
        os.environ["PYTHONPATH"] = src + (os.pathsep + old if old else "")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                code, report, hits = killer_demo.run(Path(tmp), exe=[sys.executable, "-m", "aiterprise_scan"])
        finally:
            if old is None:
                os.environ.pop("PYTHONPATH")
            else:
                os.environ["PYTHONPATH"] = old
        self.assertEqual([label for label, found in hits.items() if not found], [])
        self.assertEqual(code, 1)
        self.assertEqual(report["tool"], "aiterprise-scan")


if __name__ == "__main__":
    unittest.main()
