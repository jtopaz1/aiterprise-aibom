"""Per-file results kept between scans (design doc 13 §5.5: a warm re-scan in under 10 s)."""

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aiterprise_scan import cli, discover, licences, scancache, secrets, services  # noqa: E402
from aiterprise_scan.scanner import ScanOptions, run_scan  # noqa: E402


class Counter:
    """A per-file analysis that counts its calls."""

    def __init__(self):
        self.calls = []

    def __call__(self, text):
        self.calls.append(text)
        return [["pypi", text.upper(), text, 1]]


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "scan"
        self.target = Path(self.tmp.name) / "repo"

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, texts, compute, target=None, release=None):
        """One scan: a session over `texts`, returning the results and the session's counts."""
        with scancache.session(self.dir) as s:
            scancache.use_tree(target or self.target, release)
            got = [scancache.memo("kind", t, compute) for t in texts]
            counts = scancache.reused()
        self.assertIsNotNone(s)
        return got, counts

    def test_outside_a_session_every_call_computes(self):
        f = Counter()
        self.assertEqual(scancache.memo("kind", "a", f), [["pypi", "A", "a", 1]])
        scancache.memo("kind", "a", f)
        self.assertEqual(f.calls, ["a", "a"])

    def test_a_session_without_a_directory_computes(self):
        f = Counter()
        with scancache.session(None):
            scancache.use_tree(self.target, None)
            scancache.memo("kind", "a", f)
        with scancache.session(None):
            scancache.use_tree(self.target, None)
            scancache.memo("kind", "a", f)
        self.assertEqual(f.calls, ["a", "a"])

    def test_a_later_scan_reuses_the_results_of_unchanged_files(self):
        f = Counter()
        first, counts1 = self.scan(["a", "b"], f)
        second, counts2 = self.scan(["a", "b", "c"], f)
        self.assertEqual(first, second[:2])
        self.assertEqual(second[2], [["pypi", "C", "c", 1]])
        self.assertEqual(f.calls, ["a", "b", "c"])  # a and b were not computed again
        self.assertEqual(counts1, (0, 2))
        self.assertEqual(counts2, (2, 3))

    def test_a_changed_file_is_computed_again(self):
        f = Counter()
        self.scan(["import os\n"], f)
        got, _ = self.scan(["import torch\n"], f)
        self.assertEqual(f.calls, ["import os\n", "import torch\n"])
        self.assertEqual(got, [[["pypi", "IMPORT TORCH\n", "import torch\n", 1]]])

    def test_files_not_in_the_latest_scan_are_forgotten(self):
        f = Counter()
        self.scan(["a", "b"], f)
        self.scan(["a"], f)
        self.scan(["b"], f)
        self.assertEqual(f.calls, ["a", "b", "b"])

    def test_another_release_of_the_definitions_starts_empty(self):
        f = Counter()
        self.scan(["a"], f, release=None)
        self.scan(["a"], f, release="rel_" + "1" * 64)
        self.scan(["a"], f, release="rel_" + "1" * 64)
        self.assertEqual(f.calls, ["a", "a"])

    def test_another_build_of_the_scanner_starts_empty(self):
        f = Counter()
        self.scan(["a"], f)
        with mock.patch.object(scancache, "code_fingerprint", return_value="another build"):
            self.scan(["a"], f)
        self.assertEqual(f.calls, ["a", "a"])

    def test_each_target_has_its_own_results(self):
        f = Counter()
        self.scan(["a", "b"], f, target=self.target)
        self.scan(["a"], f, target=self.target / "sub")  # does not make the first target forget b
        self.scan(["a", "b"], f, target=self.target)
        self.assertEqual(f.calls, ["a", "b", "a"])

    def test_the_same_text_under_another_variant_is_computed_again(self):
        f = Counter()
        def scan(*variants):
            with scancache.session(self.dir):
                scancache.use_tree(self.target, None)
                for v in variants:
                    scancache.memo("kind", "a", f, variant=v)

        scan("Dockerfile", "app.py", "Dockerfile")
        self.assertEqual(f.calls, ["a", "a"])
        scan("Dockerfile")  # forgets app.py
        scan("app.py")
        self.assertEqual(f.calls, ["a", "a", "a"])

    def test_each_kind_has_its_own_results(self):
        f, g = Counter(), Counter()
        with scancache.session(self.dir):
            scancache.use_tree(self.target, None)
            scancache.memo("one", "a", f)
            scancache.memo("two", "a", g)
        self.assertEqual((f.calls, g.calls), (["a"], ["a"]))

    def test_a_damaged_cache_file_is_ignored_and_replaced(self):
        f = Counter()
        self.scan(["a"], f)
        for p in self.dir.iterdir():
            p.write_text("{not json", encoding="utf-8")
        self.scan(["a"], f)
        self.scan(["a"], f)
        self.assertEqual(f.calls, ["a", "a"])

    def test_a_cache_file_of_the_wrong_shape_is_ignored(self):
        f = Counter()
        self.scan(["a"], f)
        for p in self.dir.iterdir():
            p.write_text(json.dumps({"fingerprint": "x", "results": [1, 2]}), encoding="utf-8")
        self.scan(["a"], f)
        self.assertEqual(f.calls, ["a", "a"])

    def test_a_directory_that_cannot_be_written_is_not_an_error(self):
        blocker = Path(self.tmp.name) / "file"
        blocker.write_text("", encoding="utf-8")
        f = Counter()
        with scancache.session(blocker / "scan"):  # a directory below a file cannot be made
            scancache.use_tree(self.target, None)
            self.assertEqual(scancache.memo("kind", "a", f), [["pypi", "A", "a", 1]])

    def test_nothing_is_kept_when_the_scan_fails(self):
        f = Counter()
        with self.assertRaises(RuntimeError):
            with scancache.session(self.dir):
                scancache.use_tree(self.target, None)
                scancache.memo("kind", "a", f)
                raise RuntimeError("scan failed")
        self.assertFalse(self.dir.exists() and any(self.dir.iterdir()))

    def test_a_result_that_cannot_be_stored_is_still_returned(self):
        with scancache.session(self.dir):
            scancache.use_tree(self.target, None)
            self.assertEqual(scancache.memo("kind", "a", lambda t: {1, 2}), {1, 2})
        with scancache.session(self.dir):
            scancache.use_tree(self.target, None)
            self.assertEqual(scancache.memo("kind", "a", lambda t: {3}), {3})

    def test_results_of_targets_not_scanned_for_a_month_are_removed(self):
        f = Counter()
        self.scan(["a"], f, target=self.target / "old")
        self.scan(["a"], f, target=self.target / "kept")
        month = 31 * 24 * 3600
        for p in self.dir.iterdir():
            os.utime(p, (p.stat().st_atime - month, p.stat().st_mtime - month))
        self.scan(["a"], f, target=self.target / "kept")  # unchanged: still marked as used
        self.scan(["b"], f, target=self.target / "new")
        self.scan(["a"], f, target=self.target / "kept")
        self.scan(["a"], f, target=self.target / "old")
        self.assertEqual(f.calls, ["a", "a", "b", "a"])  # kept was reused; old was not

    def test_at_most_so_many_targets_are_kept(self):
        f = Counter()
        with mock.patch.object(scancache, "MAX_STORES", 3):
            for i in range(5):
                self.scan(["a"], f, target=self.target / str(i))
            self.assertEqual(len(list(self.dir.glob("*.json"))), 3)
            self.scan(["a"], f, target=self.target / "4")  # the latest are the ones kept
        self.assertEqual(len(f.calls), 5)

    def test_a_replaced_file_of_an_older_build_is_removed(self):
        f = Counter()
        self.scan(["a"], f)
        with mock.patch.object(scancache, "code_fingerprint", return_value="another build"):
            self.scan(["a"], f)
        self.assertEqual(len(list(self.dir.iterdir())), 1)


class FingerprintTests(unittest.TestCase):
    def test_any_change_to_the_package_changes_the_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            (pkg / "data").mkdir(parents=True)
            (pkg / "a.py").write_text("x = 1\n", encoding="utf-8")
            (pkg / "data" / "t.json").write_text("{}", encoding="utf-8")
            (pkg / "__pycache__").mkdir()
            (pkg / "__pycache__" / "a.pyc").write_bytes(b"1")
            fp = scancache.package_fingerprint(pkg)
            (pkg / "__pycache__" / "a.pyc").write_bytes(b"2")  # compiled files do not count
            self.assertEqual(scancache.package_fingerprint(pkg), fp)
            (pkg / "data" / "t.json").write_text("[]", encoding="utf-8")  # same size, other bytes
            fp2 = scancache.package_fingerprint(pkg)
            self.assertNotEqual(fp2, fp)
            (pkg / "b.py").write_text("", encoding="utf-8")
            self.assertNotEqual(scancache.package_fingerprint(pkg), fp2)

    def test_the_fingerprint_holds_the_version(self):
        with mock.patch.object(scancache, "__version__", "0.0.0-other"):
            other = scancache.package_fingerprint(Path(scancache.__file__).parent)
        self.assertNotEqual(other, scancache.package_fingerprint(Path(scancache.__file__).parent))


KEY = "qRsTuVwXyZ4KpM8NvW2JtH6LgQ9BdF3K7P"  # 34 characters after "hf_": a Hugging Face token's shape
TWIN = '// AutoModel.from_pretrained("acme/commented-out")\np = pipeline("text-generation", "acme/in-all-code")\n'

SAMPLE = {
    "app/main.py": 'import os\nimport openai\nclient = openai.OpenAI(base_url="http://10.0.0.5:8000/v1")\n',
    ".env": "OPENAI_BASE_URL=https://llm-proxy.internal.example/v1\n",
    "deploy/Dockerfile": "FROM qdrant/qdrant:v1.9.0\nENV OPENAI_BASE_URL https://gw.corp.example/v1\n",
    # the same text in files another analyzer reads, or the same analyzer reads differently
    "deploy/notes.py": "FROM qdrant/qdrant:v1.9.0\nENV OPENAI_BASE_URL https://gw.corp.example/v1\n",
    "app/twin.py": "import anthropic\n",
    "web/twin.js": "import anthropic\n",
    "app/notebook_copy.py": json.dumps({"cells": [{"cell_type": "code", "source": "import torch\n"}]}),
    "app/util.py": "import json\n",
    "nb/analysis.ipynb": json.dumps({"cells": [{"cell_type": "code", "source": "import torch\n"}]}),
    "web/index.ts": "import Anthropic from '@anthropic-ai/sdk';\n",
    # a secret, in two files with the same text, so each keeps its own location
    "config/settings.yaml": f"hf_token: hf_{KEY}\n",
    "config/copy.yaml": f"hf_token: hf_{KEY}\n",
    # model and dataset references in code and in a document; acme/tiny-model may become a folder
    "app/models.py": ('from transformers import AutoModel\nfrom datasets import load_dataset\n'
                      'm = AutoModel.from_pretrained("meta-llama/Meta-Llama-3-8B")\n'
                      'd = load_dataset("rajpurkar/squad_v2")\n'
                      'local = AutoModel.from_pretrained("acme/tiny-model")\n'),
    "web/models.js": 'const p = await pipeline("text-generation", "Xenova/gpt2");\n',
    "docs/models.md": "Weights: https://huggingface.co/google/gemma-2b\n",
    # the same text read three ways: calls in Python ("//" is no comment), not in JavaScript, links only in a document
    "app/twin_models.py": TWIN,
    "web/twin_models.js": TWIN,
    "docs/twin_models.md": TWIN,
    "nb/refs.ipynb": json.dumps({"cells": [{"cell_type": "code", "source":
                                            "# notebook cell\nm = AutoModel.from_pretrained('Qwen/Qwen2-0.5B')\n"}]}),
}
REFS = {"meta-llama/Meta-Llama-3-8B", "rajpurkar/squad_v2", "acme/tiny-model", "Xenova/gpt2", "google/gemma-2b",
        "Qwen/Qwen2-0.5B"}


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        for rel, text in SAMPLE.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        self.cache = Path(self.tmp.name) / "cache" / "scan"
        self.env = mock.patch.dict(os.environ, {"AITERPRISE_DEFS": "bundled"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def run_scan(self, cache=True):
        return run_scan(ScanOptions(target=self.root, offline=True, registry=False,
                                    file_cache=self.cache if cache else None))

    def summary(self, result):
        comps = sorted((c.ctype, c.ecosystem or "", c.name, c.version or "", json.dumps(c.properties, sort_keys=True),
                        tuple(sorted((loc.path, loc.line or 0) for loc in c.locations)))
                       for c in result.components)
        return comps, sorted(f.fingerprint for f in result.findings)

    def test_a_warm_scan_reports_what_a_cold_scan_does_without_parsing_again(self):
        cold = self.run_scan()
        seen: list[str] = []

        def spy(real):
            def analyse(text, *args, **kwargs):
                seen.append(text)
                return real(text, *args, **kwargs)
            return analyse

        with mock.patch.object(discover, "_python_hits", side_effect=AssertionError("parsed")), \
                mock.patch.object(discover, "_notebook_hits", side_effect=AssertionError("parsed")), \
                mock.patch.object(discover, "_js_hits", side_effect=AssertionError("parsed")), \
                mock.patch.object(services, "_scan_text", side_effect=AssertionError("read")), \
                mock.patch.object(secrets, "find_secrets", spy(secrets.find_secrets)), \
                mock.patch.object(licences, "_scan_calls", spy(licences._scan_calls)), \
                mock.patch.object(licences, "_scan_urls", spy(licences._scan_urls)):
            warm = self.run_scan()
        # notebooks are read for model references every time (their lines depend on what is kept)
        texts = set(SAMPLE.values())  # as written; on Windows the files hold CRLF line ends
        again = [t for t in seen if t.replace("\r\n", "\n") in texts and not t.startswith('{"cells"')]
        self.assertEqual(again, [])
        self.assertTrue(seen)  # the notebooks were
        self.assertEqual(self.summary(warm), self.summary(cold))
        self.assertEqual(self.summary(warm), self.summary(self.run_scan(cache=False)))
        names = {c.name for c in warm.components}
        self.assertTrue({"openai", "torch", "@anthropic-ai/sdk"} | REFS <= names, names)
        endpoints = {c.name for c in warm.components if c.ctype == "ai-endpoint"}
        self.assertEqual(endpoints, {"http://10.0.0.5:8000", "https://llm-proxy.internal.example",
                                     "https://gw.corp.example"})
        self.assertIn("vector-store", {c.ctype for c in warm.components})
        where = {c.name: sorted(loc.path for loc in c.locations) for c in warm.components}
        self.assertEqual(where["acme/commented-out"], ["app/twin_models.py"])
        self.assertEqual(where["acme/in-all-code"], ["app/twin_models.py", "web/twin_models.js"])  # not the .md
        found = sorted((f.rule_id, f.location.path, f.location.line) for f in warm.findings
                       if f.rule_id.startswith("ait.secret."))
        self.assertEqual(found, [("ait.secret.huggingface", "config/copy.yaml", 1),
                                 ("ait.secret.huggingface", "config/settings.yaml", 1)])

    def test_a_reference_that_is_now_a_local_folder_is_dropped_by_a_warm_scan(self):
        self.assertIn("acme/tiny-model", {c.name for c in self.run_scan().components})
        (self.root / "acme" / "tiny-model").mkdir(parents=True)  # no file in it: the scanned files are the same
        (self.root / "google" / "gemma-2b").mkdir(parents=True)  # a link is a reference whatever the folders
        warm = self.run_scan()
        reused, used = self.cache_note(warm)
        self.assertEqual(reused, used)
        names = {c.name for c in warm.components}
        self.assertNotIn("acme/tiny-model", names)
        self.assertTrue({"meta-llama/Meta-Llama-3-8B", "google/gemma-2b"} <= names, names)
        self.assertEqual(self.summary(warm), self.summary(self.run_scan(cache=False)))

    def test_kept_secret_results_hold_only_what_the_report_shows(self):
        self.run_scan()
        kept = "".join(p.read_text(encoding="utf-8") for p in self.cache.glob("*.json"))
        digest = secrets._digest(f"hf_{KEY}")
        self.assertNotIn(KEY, kept)
        self.assertNotIn(digest, kept)  # the report shows 8 of its 16 characters
        self.assertIn(digest[:8], kept)
        self.assertIn(secrets.redact(f"hf_{KEY}"), kept)

    def cache_note(self, result):
        notes = [n for n in result.notes if n.startswith("file cache")]
        if not notes:
            return None
        m = re.fullmatch(r"file cache: ([0-9,]+) of ([0-9,]+) per-file results are from an earlier scan of "
                         r"this target with the same scanner and definitions", notes[0])
        self.assertTrue(m, notes[0])
        return int(m.group(1).replace(",", "")), int(m.group(2).replace(",", ""))

    def test_the_report_says_how_many_results_came_from_an_earlier_scan(self):
        self.assertIsNone(self.cache_note(self.run_scan()))
        reused, used = self.cache_note(self.run_scan())
        self.assertEqual(reused, used)
        self.assertGreaterEqual(used, 9)  # 4 sources for imports, 5 files for endpoints and stores

    def test_a_changed_file_is_read_again(self):
        self.run_scan()
        (self.root / "app" / "util.py").write_text("import json\nimport anthropic\n", encoding="utf-8")
        warm = self.run_scan()
        self.assertIn("anthropic", {c.name for c in warm.components})
        reused, used = self.cache_note(warm)
        self.assertEqual(reused, used - 4)  # util.py: its imports, endpoints, secrets and model references

    def test_no_cache_unless_asked(self):
        self.run_scan(cache=False)
        self.assertFalse(self.cache.exists())


class _Captured(Exception):
    pass


class CliTests(unittest.TestCase):
    def options(self, argv, runner="_gated_scan"):
        captured = {}

        def fake(opts, *args, **kwargs):
            captured["opts"] = opts
            raise _Captured

        with mock.patch.object(cli, runner, side_effect=fake), \
                mock.patch.dict(os.environ, {"AITERPRISE_CACHE_DIR": "/tmp/aiterprise-cache"}):
            with self.assertRaises(_Captured):
                cli.main(argv)
        return captured["opts"]

    def test_scan_keeps_file_results_in_the_cache_directory(self):
        opts = self.options(["scan", ".", "--offline"])
        self.assertEqual(opts.file_cache, Path("/tmp/aiterprise-cache") / "scan")

    def test_no_cache_turns_it_off(self):
        self.assertIsNone(self.options(["scan", ".", "--offline", "--no-cache"]).file_cache)

    def test_bom_uses_it_too(self):
        self.assertEqual(self.options(["bom", "."], runner="run_scan").file_cache,
                         Path("/tmp/aiterprise-cache") / "scan")
        self.assertIsNone(self.options(["bom", ".", "--no-cache"], runner="run_scan").file_cache)


if __name__ == "__main__":
    unittest.main()
