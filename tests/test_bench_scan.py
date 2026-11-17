"""tools/bench_scan.py: the monorepo it builds and the numbers it reports."""

import io
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import bench_scan  # noqa: E402


class BuildTreeTests(unittest.TestCase):
    def test_exact_file_count_with_the_planted_problems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mono"
            info = bench_scan.build_tree(root, 250)
            files = [p for p in root.rglob("*") if p.is_file()]
            self.assertEqual(len(files), 250)
            self.assertEqual(info["files"], 250)
            self.assertEqual(info["bytes"], sum(p.stat().st_size for p in files))
            self.assertTrue((root / bench_scan.PLANTED / "model.pt").is_file())
            kinds = Counter(p.suffix for p in files)
            self.assertGreater(kinds[".py"], 150)
            self.assertGreater(kinds[".ts"] + kinds[".js"], 0)
            self.assertGreater(kinds[".md"], 0)

    def test_the_same_tree_every_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a", Path(tmp) / "b"
            bench_scan.build_tree(a, 120)
            bench_scan.build_tree(b, 120)
            listing = lambda r: sorted((p.relative_to(r).as_posix(), p.stat().st_size)  # noqa: E731
                                       for p in r.rglob("*") if p.is_file())
            self.assertEqual(listing(a), listing(b))

    def test_too_few_files_for_the_planted_package_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                bench_scan.build_tree(Path(tmp) / "mono", 10)


class RunTests(unittest.TestCase):
    def test_two_timed_scans_that_find_all_five(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = bench_scan.run(Path(tmp), 200)
        self.assertEqual(res["files"], 200)
        self.assertEqual(res["exit"], [1, 1])
        self.assertEqual(res["missed"], [])
        self.assertEqual(len(res["seconds"]), 2)
        self.assertTrue(all(s > 0 for s in res["seconds"]))
        if sys.platform != "win32":
            self.assertGreater(res["peak_rss_mb"], 10)

    def test_check_fails_over_the_budget_or_on_a_miss(self):
        ok = {"files": 10, "bytes": 1, "seconds": [5.0, 4.0], "exit": [1, 1], "missed": [], "python": "3"}
        self.assertEqual(bench_scan.problems(ok, budget=60), [])
        self.assertTrue(bench_scan.problems({**ok, "seconds": [61.0, 4.0]}, budget=60))
        self.assertTrue(bench_scan.problems({**ok, "missed": ["unsafe pickle in model.pt"]}, budget=60))
        self.assertTrue(bench_scan.problems({**ok, "exit": [2, 1]}, budget=60))

    def test_check_warm_fails_when_the_re_scan_is_over_its_budget(self):
        ok = {"files": 10, "bytes": 1, "seconds": [50.0, 9.0], "exit": [1, 1], "missed": [], "python": "3"}
        self.assertEqual(bench_scan.problems(ok, budget=60, warm_budget=10), [])
        self.assertEqual(bench_scan.problems({**ok, "seconds": [50.0, 11.0]}, budget=60),
                         [])  # no warm budget given
        self.assertEqual(bench_scan.problems({**ok, "seconds": [50.0, 11.0]}, budget=60, warm_budget=10),
                         ["the second scan took 11.0 s, over the 10 s budget for a re-scan of an unchanged tree"])

    def test_an_online_run_scans_without_offline(self):
        cmds, envs = [], []

        def fake_run(cmd, **kwargs):
            cmds.append(cmd)
            envs.append(kwargs["env"])
            return mock.Mock(returncode=1)

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(bench_scan.subprocess, "run", fake_run), \
                mock.patch.dict(bench_scan.os.environ, {"AITERPRISE_API_KEY": "k", "AITERPRISE_HOME": "/elsewhere"}):
            bench_scan._scan(Path(tmp), Path(tmp) / "out", Path(tmp) / "cache", None)
            bench_scan._scan(Path(tmp), Path(tmp) / "out", Path(tmp) / "cache", None, online=True)
        self.assertIn("--offline", cmds[0])
        self.assertNotIn("--offline", cmds[1])
        for env in envs:  # no SecDB: neither a key in the environment nor a stored login
            self.assertNotIn("AITERPRISE_API_KEY", env)
            self.assertEqual(env["AITERPRISE_HOME"], str(Path(tmp) / "home"))

    def test_an_online_run_must_show_the_live_sources_answered(self):
        offline_report = {"mode": "offline", "findings": [], "examined": {}}
        online_report = {"mode": "online", "findings": [],
                         "examined": {"osv": {"checked": 4, "with_data": 1}, "registry": {"checked": 4, "with_data": 4}}}
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(bench_scan, "_scan", return_value=(1.0, 1, offline_report)):
                res = bench_scan.run(Path(tmp) / "a", 120, online=True)
            self.assertIn("the report says mode offline, not online", bench_scan.problems(res, budget=120))
            with mock.patch.object(bench_scan, "_scan", return_value=(1.0, 1, online_report)):
                res = bench_scan.run(Path(tmp) / "b", 120, online=True)
            self.assertEqual(res["online"], True)
            self.assertEqual(res["mode"], [])
            no_registry = {**online_report, "examined": {"osv": {"checked": 4, "with_data": 1},
                                                         "registry": {"checked": 0, "with_data": 0, "errors": 4}}}
            with mock.patch.object(bench_scan, "_scan", return_value=(1.0, 1, no_registry)) as scan:
                res = bench_scan.run(Path(tmp) / "d", 120, online=True)
            self.assertEqual([c.kwargs.get("online") for c in scan.call_args_list], [True, True])
            self.assertEqual(res["mode"], ["registry was not consulted (4 failed lookups)"])  # once, not per scan
            self.assertIn("registry was not consulted (4 failed lookups)", bench_scan.problems(res, budget=120))
            for i, scans in enumerate([[online_report, no_registry], [no_registry, online_report]]):
                with mock.patch.object(bench_scan, "_scan", side_effect=[(1.0, 1, r) for r in scans]):
                    res = bench_scan.run(Path(tmp) / f"e{i}", 120, online=True)
                self.assertEqual(res["mode"], ["registry was not consulted (4 failed lookups)"])  # either scan counts
            with mock.patch.object(bench_scan, "_scan", return_value=(1.0, 1, offline_report)):
                res = bench_scan.run(Path(tmp) / "c", 120)  # offline: an offline report is right
            self.assertEqual(res["mode"], [])
            self.assertEqual(res["online"], False)

    def test_the_command_line_runs_online_and_fails_on_a_mode_problem(self):
        res = {"files": 10, "bytes": 1, "seconds": [5.0, 4.0], "exit": [1, 1], "missed": [], "python": "3",
               "platform": "x", "online": True, "mode": ["osv was not consulted (missing)"], "peak_rss_mb": None}
        with mock.patch.object(bench_scan, "run", return_value=res) as run, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            code = bench_scan.main(["--files", "10", "--online", "--check", "120", "--work", "w"])
        self.assertEqual(run.call_args.kwargs["online"], True)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  osv was not consulted (missing)", out.getvalue())
        self.assertIn("mode: online", out.getvalue())

    def test_the_second_scan_reuses_what_the_first_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            bench_scan.run(Path(tmp), 200)
            kept = list((Path(tmp) / "cache" / "scan").glob("*.json"))
        self.assertTrue(kept)


if __name__ == "__main__":
    unittest.main()
