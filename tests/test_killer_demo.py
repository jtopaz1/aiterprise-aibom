"""The design doc 13 §3 killer demo as an acceptance test: one offline scan finds all five, and an
online run counts only if the report shows the live sources answered."""

import importlib.util
import io
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
        self.assertEqual(killer_demo.mode_problems(report, online=False), [])

    def test_an_online_run_must_have_asked_the_live_sources(self):
        live = {"mode": "online", "examined": {"osv": {"checked": 4, "with_data": 2},
                                               "registry": {"checked": 4, "with_data": 4}}}
        self.assertEqual(killer_demo.mode_problems(live, online=True), [])
        # the network was not reached, or the scan quietly ran offline: the five hits prove nothing online
        quiet = {"mode": "online", "examined": {"osv": {"checked": 0, "with_data": 0, "skipped": "offline (cache only)"},
                                                "registry": {"checked": 4, "with_data": 4}}}
        self.assertEqual(killer_demo.mode_problems(quiet, online=True),
                         ["osv was not consulted (offline (cache only))"])
        self.assertEqual(killer_demo.mode_problems({**live, "mode": "offline"}, online=True),
                         ["the report says mode offline, not online"])
        self.assertEqual(killer_demo.mode_problems({"mode": "online", "examined": {}}, online=True),
                         ["osv was not consulted (missing)", "registry was not consulted (missing)"])
        # what an online scan with no network reports: the five still hit from bundled data, exit 1
        unreachable = {"mode": "online", "examined": {"osv": {"checked": 0, "with_data": 0, "errors": 1},
                                                      "registry": {"checked": 0, "with_data": 0, "errors": 4}}}
        self.assertEqual(killer_demo.mode_problems(unreachable, online=True),
                         ["osv was not consulted (1 failed lookups)", "registry was not consulted (4 failed lookups)"])

    def test_the_demo_fails_when_an_online_run_did_not_reach_the_network(self):
        from unittest import mock

        quiet = {"mode": "online", "findings": [],
                 "examined": {"osv": {"checked": 0, "with_data": 0, "errors": 1},
                              "registry": {"checked": 4, "with_data": 4}}}
        all_hit = {label: [{"severity": "critical"}] for label in killer_demo.EXPECT}
        answered = {**quiet, "examined": {"osv": {"checked": 4}, "registry": {"checked": 4}}}
        with tempfile.TemporaryDirectory() as work:
            with mock.patch.object(killer_demo, "run", return_value=(1, quiet, all_hit)), \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(killer_demo.main(["--online", "--work", work]), 1)
            self.assertIn("MODE  osv was not consulted (1 failed lookups)", out.getvalue())
            with mock.patch.object(killer_demo, "run", return_value=(1, answered, all_hit)), \
                    mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(killer_demo.main(["--online", "--work", work]), 0)

    def test_an_offline_run_must_not_have_asked_the_live_sources(self):
        leaked = {"mode": "offline", "examined": {"osv": {"checked": 0, "with_data": 0, "skipped": "offline"},
                                                  "registry": {"checked": 4, "with_data": 4}}}
        self.assertEqual(killer_demo.mode_problems(leaked, online=False), ["registry was consulted offline"])

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
