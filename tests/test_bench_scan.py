"""tools/bench_scan.py: the monorepo it builds and the numbers it reports."""

import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
