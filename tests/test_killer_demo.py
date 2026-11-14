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


if __name__ == "__main__":
    unittest.main()
