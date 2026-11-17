"""tools/bench_models.py: the model files it writes are what they claim to be, and its verdict."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import modelfiles


def _tool(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bench = _tool("bench_models")
MIB = 1 << 20


class BuildTests(unittest.TestCase):
    """Each case is a well-formed file of its format, of the size asked for, with nothing to find."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, case, nbytes):
        path = bench.build(case, self.dir, nbytes)
        component, findings = modelfiles.analyze_model_file(path, self.dir)
        return path, component, findings

    def test_every_case_is_inventoried_as_its_format_with_only_the_expected_finding(self):
        for case, fmt in bench.FORMATS.items():
            with self.subTest(case=case):
                path, component, findings = self.analyze(case, 3 * MIB)
                self.assertIsNotNone(component)
                self.assertEqual(component.properties["format"], fmt)
                self.assertEqual(sorted(f.rule_id for f in findings), bench.EXPECTED_FINDINGS[case])
        self.assertEqual(bench.EXPECTED_FINDINGS["safetensors"], [])
        self.assertEqual(bench.EXPECTED_FINDINGS["pickle"], ["ait.model.pickle.format"])  # info only

    def test_the_tensor_data_is_the_size_asked_for(self):
        for case in bench.FORMATS:
            with self.subTest(case=case):
                path = bench.build(case, self.dir / case, 5 * MIB + 3)
                self.assertGreaterEqual(path.stat().st_size, 5 * MIB + 3)
                self.assertLess(path.stat().st_size, 5 * MIB + 3 + 4096)  # headers only

    def test_the_pickles_are_walked_not_skipped(self):
        for case, globals_ in (("pytorch-zip", "torch._utils._rebuild_tensor_v2"),
                               ("pickle", "numpy.core.multiarray._reconstruct")):
            with self.subTest(case=case):
                _, component, _ = self.analyze(case, MIB)
                self.assertIn(globals_, component.properties.get("pickle_globals", []))


class VerdictTests(unittest.TestCase):
    def result(self, **over):
        res = {"cases": {case: {"bytes": 2 << 30, "seconds": 1.0, "exit": 0, "format": fmt,
                                "findings": list(bench.EXPECTED_FINDINGS[case])}
                         for case, fmt in bench.FORMATS.items()}}
        for case, change in over.items():
            res["cases"][case].update(change)
        return res

    def test_a_fast_clean_run_passes(self):
        self.assertEqual(bench.problems(self.result()), [])

    def test_the_safetensors_budget_is_5_s_for_2_gib(self):
        self.assertEqual(bench.problems(self.result(safetensors={"seconds": 4.9})), [])
        self.assertTrue(any("safetensors" in p for p in bench.problems(self.result(safetensors={"seconds": 5.1}))))

    def test_the_pickle_budget_is_30_s_per_gib(self):
        one_gib = {"bytes": 1 << 30}
        self.assertEqual(bench.problems(self.result(pickle={**one_gib, "seconds": 29.0})), [])
        self.assertTrue(bench.problems(self.result(pickle={**one_gib, "seconds": 31.0})))
        self.assertTrue(bench.problems(self.result(**{"pytorch-zip": {**one_gib, "seconds": 31.0}})))

    def test_a_wrong_format_a_finding_or_another_exit_fails(self):
        self.assertTrue(bench.problems(self.result(pickle={"format": "unknown"})))
        self.assertTrue(bench.problems(self.result(safetensors={"findings": ["ait.model.malformed"]})))
        self.assertTrue(bench.problems(self.result(pickle={"findings": []})))  # the format finding went missing
        self.assertTrue(bench.problems(self.result(**{"pytorch-zip": {"exit": 2}})))
        self.assertTrue(bench.problems(self.result(pickle={"format": None})))  # not inventoried at all


if __name__ == "__main__":
    unittest.main()
