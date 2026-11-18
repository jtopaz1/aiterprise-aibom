"""The release's last look at the wheel and sdist before PyPI gets them (`tools/check_dist.py`)."""

import contextlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_dist", ROOT / "tools" / "check_dist.py")
check_dist = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_dist)

V = "9.9.9"
PYPROJECT = """\
[tool.setuptools.package-data]
aiterprise_scan = ["data/ait/*.json", "data/ait/*.json.gz"]
"""
SOURCE = {
    "src/aiterprise_scan/__init__.py": f'"""x"""\n\n__version__ = "{V}"\n',
    "src/aiterprise_scan/cli.py": "",
    "src/aiterprise_scan/sub/__init__.py": "",
    "src/aiterprise_scan/data/ait/rules.json": "{}",
    "src/aiterprise_scan/data/ait/big.json.gz": "",
    "src/aiterprise_scan/data/ait/notes.txt": "not package data",
    "pyproject.toml": PYPROJECT,
}
DESCRIPTION = "Metadata-Version: 2.4\nName: aiterprise-scan\nVersion: 9.9.9\n\n# AIterprise\n\nScan things.\n"


def sdist_members():
    p = f"aiterprise_scan-{V}/"
    out = {p + "PKG-INFO": DESCRIPTION}
    for name in ("README.md", "LICENSE", "NOTICE", "pyproject.toml", "setup.cfg", "MANIFEST.in"):
        out[p + name] = ""
    for rel, text in SOURCE.items():
        if rel.startswith("src/") and not rel.endswith(".txt"):
            out[p + rel] = text
    out[p + "src/aiterprise_scan.egg-info/PKG-INFO"] = DESCRIPTION
    return out


def wheel_members():
    out = {rel[len("src/"):]: text for rel, text in SOURCE.items() if rel.startswith("src/") and not rel.endswith(".txt")}
    d = f"aiterprise_scan-{V}.dist-info/"
    out.update({d + "METADATA": DESCRIPTION, d + "WHEEL": "", d + "RECORD": "", d + "entry_points.txt": ""})
    return out


class Dist:
    """A fake source tree and a dist folder holding one sdist and one wheel built from it."""

    def __init__(self, sdist=None, wheel=None, sdist_name=f"aiterprise_scan-{V}.tar.gz",
                 wheel_name=f"aiterprise_scan-{V}-py3-none-any.whl"):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.root, self.dist = base / "repo", base / "dist"
        for rel, text in SOURCE.items():
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text(text, encoding="utf-8")
        self.dist.mkdir()
        if sdist_name:
            with tarfile.open(self.dist / sdist_name, "w:gz") as tar:
                for name, text in (sdist if sdist is not None else sdist_members()).items():
                    data = text.encode("utf-8")
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
        if wheel_name:
            with zipfile.ZipFile(self.dist / wheel_name, "w") as whl:
                for name, text in (wheel if wheel is not None else wheel_members()).items():
                    whl.writestr(name, text)

    def problems(self, **kw):
        return check_dist.problems(self.dist, root=self.root, **kw)

    def close(self):
        self._tmp.cleanup()


class CheckDistTests(unittest.TestCase):
    def dist(self, **kw):
        d = Dist(**kw)
        self.addCleanup(d.close)
        return d

    def assertProblem(self, problems, *words):
        self.assertTrue(any(all(w in p for w in words) for p in problems), (words, problems))

    def test_a_pair_built_from_the_tree_passes(self):
        self.assertEqual(self.dist().problems(), [])

    def test_tests_in_the_sdist_are_refused(self):
        s = sdist_members()
        s[f"aiterprise_scan-{V}/tests/test_x.py"] = ""
        self.assertProblem(self.dist(sdist=s).problems(), "sdist", "tests/test_x.py")

    def test_an_unexpected_top_level_file_in_the_sdist_is_refused(self):
        s = sdist_members()
        s[f"aiterprise_scan-{V}/.env"] = "KEY=1"
        self.assertProblem(self.dist(sdist=s).problems(), "sdist", ".env")

    def test_compiled_files_are_refused(self):
        w = wheel_members()
        w["aiterprise_scan/__pycache__/cli.cpython-311.pyc"] = ""
        self.assertProblem(self.dist(wheel=w).problems(), "wheel", "__pycache__")
        s = sdist_members()
        s[f"aiterprise_scan-{V}/src/aiterprise_scan/cli.pyc"] = ""
        self.assertProblem(self.dist(sdist=s).problems(), "sdist", "cli.pyc")

    def test_a_file_outside_the_package_in_the_wheel_is_refused(self):
        w = wheel_members()
        w["notes.txt"] = ""
        self.assertProblem(self.dist(wheel=w).problems(), "wheel", "notes.txt")

    def test_a_missing_data_file_is_refused(self):
        w = wheel_members()
        del w["aiterprise_scan/data/ait/big.json.gz"]
        self.assertProblem(self.dist(wheel=w).problems(), "wheel", "data/ait/big.json.gz")
        s = sdist_members()
        del s[f"aiterprise_scan-{V}/src/aiterprise_scan/data/ait/rules.json"]
        self.assertProblem(self.dist(sdist=s).problems(), "sdist", "data/ait/rules.json")

    def test_a_missing_module_is_refused(self):
        w = wheel_members()
        del w["aiterprise_scan/sub/__init__.py"]
        self.assertProblem(self.dist(wheel=w).problems(), "wheel", "sub/__init__.py")

    def test_a_file_that_is_not_package_data_is_not_required(self):
        self.assertNotIn("notes.txt", " ".join(self.dist().problems()))

    def test_exactly_one_of_each_for_this_version(self):
        self.assertProblem(self.dist(wheel_name=None).problems(), "wheel", V)
        self.assertProblem(self.dist(sdist_name=None).problems(), "sdist", V)
        self.assertProblem(self.dist(wheel_name="aiterprise_scan-1.0.0-py3-none-any.whl").problems(), "1.0.0")

    def test_other_files_in_the_dist_folder_are_left_alone(self):
        d = self.dist()
        (d.dist / f"aiterprise-scan-v{V}.cdx.json").write_text("{}", encoding="utf-8")
        self.assertEqual(d.problems(), [])

    def test_a_release_refuses_a_description_that_says_it_is_unreleased(self):
        note = DESCRIPTION + "\n> **Not released yet.** Nothing is published so far.\n"
        w, s = wheel_members(), sdist_members()
        w[f"aiterprise_scan-{V}.dist-info/METADATA"] = note
        s[f"aiterprise_scan-{V}/PKG-INFO"] = note
        d = self.dist(wheel=w, sdist=s)
        self.assertEqual(d.problems(), [])
        self.assertProblem(d.problems(release=True), "wheel", "Not released yet")
        self.assertProblem(d.problems(release=True), "sdist", "Not released yet")

    def test_main_exit_code(self):
        good = self.dist()
        s = sdist_members()
        s[f"aiterprise_scan-{V}/tests/test_x.py"] = ""
        bad = self.dist(sdist=s)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(check_dist.main([str(good.dist), "--root", str(good.root)]), 0)
            self.assertEqual(check_dist.main([str(bad.dist), "--root", str(bad.root)]), 1)
        self.assertIn("tests/test_x.py", out.getvalue())


if __name__ == "__main__":
    unittest.main()
