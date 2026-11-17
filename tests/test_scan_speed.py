"""Scan speed without changed results (design doc 13 §5.5: cold scan of a 10,000-file monorepo
under 60 s).

Each optimisation here is exact: a test pins that the expensive work is skipped, and another that
the result is what the slow path gave.
"""

import ast
import hashlib
import io
import os
import pathlib
import sys
import tempfile
import unittest
import warnings
from collections import Counter
from pathlib import Path
from unittest import mock

from aiterprise_scan import discover, modelfiles, scanner, secrets, textio

SRC = Path(__file__).resolve().parents[1] / "src" / "aiterprise_scan"

POOL = "qRsTuVwXyZ4KpM8NvW2JtH6LgQ9BdF3K7PxMzNvTqWyLd" * 4
UPOOL = "QRSTUVWXYZ4KPM8NVW2JTH6LGQ9BDF3K7PXMZ" * 2

# one sample per secret rule, found by exactly that rule
RULE_SAMPLES = {
    "openai-project": "sk-proj-" + POOL[:40],
    "openai-service": "sk-svcacct-" + POOL[:40],
    "anthropic": "sk-ant-api03-" + POOL[:50],
    "openai-legacy": "sk-" + POOL[:48],
    "huggingface": "hf_" + POOL[:34],
    "github-pat": "ghp_" + POOL[:36],
    "github-oauth": "gho_" + POOL[:36],
    "github-fine-grained": "github_pat_" + POOL[:70],
    "xai": "xai-" + POOL[:40],
    "groq": "gsk_" + POOL[:52],
    "replicate": "r8_" + POOL[:40],
    "aws-access-key": "ASIA" + UPOOL[:16],
    "google-api-key": "AIza" + POOL[:35],
    "slack-token": "xoxb-" + POOL[:24],
    "private-key-pem": "-----BEGIN EC PRIVATE KEY-----",
}


class _Spy:
    """A compiled regex that counts its scans."""

    def __init__(self, rx, calls):
        self.rx, self.calls = rx, calls

    def finditer(self, text):
        self.calls.append(self.rx.pattern)
        return self.rx.finditer(text)


class SecretPrefilterTests(unittest.TestCase):
    def test_every_rule_has_a_sample_found_by_that_rule(self):
        self.assertEqual({r[0] for r in secrets._RULES}, set(RULE_SAMPLES))
        for rule_id, value in RULE_SAMPLES.items():
            with self.subTest(rule=rule_id):
                found = [m.rule_id for m in secrets.find_secrets(f"key = {value}\n")]
                self.assertEqual(found, [rule_id])
                if rule_id != "private-key-pem":  # a PEM header is its own preview
                    self.assertNotIn(value, secrets.redact_secrets_in(f"key = {value}"))

    def test_no_rule_regex_runs_on_text_without_its_prefix(self):
        calls: list[str] = []
        spied = [(*r[:-1], _Spy(r[-1], calls)) for r in secrets._RULES]
        text = "def handler(event):\n    return task_queue.put(event)  # nothing secret here\n" * 500
        with mock.patch.object(secrets, "_RULES", spied):
            self.assertEqual(secrets.find_secrets(text), [])
            self.assertEqual(secrets.redact_secrets_in(text), text)
        self.assertEqual(calls, [])

    def test_only_the_rules_whose_prefix_occurs_are_run(self):
        calls: list[str] = []
        spied = [(*r[:-1], _Spy(r[-1], calls)) for r in secrets._RULES]
        with mock.patch.object(secrets, "_RULES", spied):
            found = secrets.find_secrets("token = " + RULE_SAMPLES["huggingface"])
        self.assertEqual([m.rule_id for m in found], ["huggingface"])
        self.assertEqual(len(calls), 1)


def _reference_imports(source: str) -> list[tuple[str, int]]:
    """discover._python_imports as it was before the statement-only walk: every node visited."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return discover._python_imports_regex(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            for alias in node.names:
                found.append((node.module if alias.name == "*" else f"{node.module}.{alias.name}", node.lineno))
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            fname = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            arg = node.args[0]
            if fname in ("import_module", "__import__") and isinstance(arg, ast.Constant) \
                    and isinstance(arg.value, str) and not arg.value.startswith("."):
                found.append((arg.value, node.lineno))
    found.sort(key=lambda t: t[1])
    return found


NESTED = '''\
"""import fake_in_docstring"""
import os, sys as system
from torch import nn, optim
from . import local
from .. import parent
from transformers import *
try:
    import openai
except ImportError:
    import anthropic
else:
    import cohere
finally:
    import mistralai
if True:
    import langchain
elif False:
    import llama_index
else:
    import vllm
for _ in ():
    import peft
else:
    import trl
while False:
    import accelerate
else:
    import datasets
with open(os.devnull) as fh:
    import tiktoken
async def run():
    async with ctx() as c:
        import groq
    async for x in it():
        import together
class Model:
    import sentence_transformers
    def fit(self, data=lambda: None):
        import xgboost; import lightgbm
match os.name:
    case "nt":
        import onnxruntime
    case _:
        import tensorflow
try:
    pass
except* ValueError:
    import keras
s = "import not_a_module"
'''


class ImportWalkTests(unittest.TestCase):
    def test_nested_imports_match_the_full_walk(self):
        got = discover._python_imports(NESTED)
        self.assertEqual(got, _reference_imports(NESTED))
        names = {m for m, _ in got}
        for expected in ("openai", "anthropic", "cohere", "mistralai", "vllm", "trl", "datasets",
                         "tiktoken", "groq", "together", "sentence_transformers", "lightgbm",
                         "onnxruntime", "tensorflow", "keras", "torch.nn", "transformers"):
            self.assertIn(expected, names)
        self.assertNotIn("fake_in_docstring", names)
        self.assertNotIn("not_a_module", names)

    def test_dynamic_imports_still_found(self):
        src = 'import importlib\nm = importlib.import_module("torch")\nn = __import__("openai")\n'
        self.assertEqual(discover._python_imports(src), _reference_imports(src))
        self.assertIn(("torch", 2), discover._python_imports(src))

    def test_expressions_are_not_walked_without_a_dynamic_import(self):
        src = "import torch\n" + "x = [f(a, b) for a in range(3) for b in range(4)]\n" * 50
        with mock.patch.object(discover.ast, "walk", side_effect=AssertionError("full walk")):
            self.assertEqual(discover._python_imports(src), [("torch", 1)])

    def test_same_result_as_the_full_walk_on_real_code(self):
        files = sorted(SRC.rglob("*.py")) + sorted(Path(os.__file__).parent.glob("*.py"))[:150]
        self.assertGreater(len(files), 100)
        for path in files:
            src = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(file=path.name):
                self.assertEqual(discover._python_imports(src), _reference_imports(src))


class ImportPrefilterTests(unittest.TestCase):
    def setUp(self):
        self.imap = discover.taxonomy.python_import_map()
        self.words = discover._ai_import_words(self.imap)

    def hits(self, src, words):
        return discover._python_hits(src, self.imap, words)

    def test_a_file_naming_no_ai_package_is_not_parsed(self):
        src = "import os\nimport json\n\ndef main():\n    return os.getcwd()\n" * 40
        with mock.patch.object(discover.ast, "parse", side_effect=AssertionError("parsed")):
            self.assertEqual(self.hits(src, self.words), [])

    def test_ai_imports_are_still_found(self):
        for src, dist in (("import torch\n", "torch"),
                          ("from google import generativeai as genai\n", "google-generativeai"),
                          ("import os, \\\n    openai\n", "openai"),
                          ("from autogen_core import Agent\n", "autogen-core"),
                          ("import Torch\n", None)):
            with self.subTest(src=src):
                got = [h[1] for h in self.hits(src, self.words)]
                self.assertEqual(got, [h[1] for h in self.hits(src, None)])
                if dist:
                    self.assertIn(dist, got)

    def test_an_identifier_python_normalises_is_still_found(self):
        src = "import \uff54\uff4f\uff52\uff43\uff48\n"  # fullwidth "torch": Python reads it as torch
        self.assertEqual([h[1] for h in self.hits(src, self.words)], ["torch"])

    def test_a_dynamic_import_is_still_found(self):
        src = 'import importlib\nm = importlib.import_module("\\x74orch")\n'
        self.assertEqual([h[1] for h in self.hits(src, self.words)], ["torch"])

    def test_same_hits_as_without_the_prefilter_on_real_code(self):
        files = sorted(SRC.rglob("*.py")) + sorted(Path(os.__file__).parent.glob("*.py"))[:150]
        files += sorted((Path(__file__).parent / "golden").rglob("*.py"))
        for path in files:
            src = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(file=path.name):
                self.assertEqual(self.hits(src, self.words), self.hits(src, None))

    def test_the_word_list_is_short_and_covers_every_package(self):
        self.assertLess(len(self.words), 120)
        for name in discover.taxonomy.ai_names("pypi"):
            self.assertTrue(any(w in name.replace("-", "_") for w in self.words), name)


class _NoScan:
    """Stands in for a compiled regex that must not be run."""

    pattern = "(not run)"

    def finditer(self, text, *args):
        raise AssertionError("regex run")

    findall = search = match = finditer


class ModelRefAndServicePrefilterTests(unittest.TestCase):
    PLAIN = "def handler(event):\n    return {'url': 'https://example.com/a', 'n': 1}\n" * 200

    def test_model_ref_regexes_skip_text_without_their_literals(self):
        from aiterprise_scan import licences

        with mock.patch.object(licences, "_CALL_RE", _NoScan()), \
                mock.patch.object(licences, "_HF_URL_RE", _NoScan()), \
                mock.patch.object(licences, "_HF_PROTO_RE", _NoScan()):
            self.assertEqual(licences._scan_calls(self.PLAIN, None, python=True), [])
            self.assertEqual(licences._scan_urls(self.PLAIN), [])

    def test_model_refs_are_still_found(self):
        from aiterprise_scan import licences

        src = ('m = AutoModel.from_pretrained("meta-llama/Llama-3.1-8B")\n'
               'url = "https://huggingface.co/mistralai/Mistral-7B-v0.1"\n'
               'p = "hf://datasets/HuggingFaceFW/fineweb"\n')
        ids = {r.hf_id for r in licences._scan_calls(src, None, python=True) + licences._scan_urls(src)}
        self.assertEqual(ids, {"meta-llama/Llama-3.1-8B", "mistralai/Mistral-7B-v0.1", "HuggingFaceFW/fineweb"})

    def test_endpoint_env_regex_skips_text_without_an_endpoint_variable(self):
        from aiterprise_scan import services

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text(self.PLAIN, encoding="utf-8")
            with mock.patch.object(services, "_env_re", lambda: _NoScan()):
                services._scan_file(services._Found(), path, "app.py")

    def test_endpoint_variables_are_still_found(self):
        from aiterprise_scan import services

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('import os\nOPENAI_BASE_URL = "https://llm.internal.example:8443/v1"\n',
                                         encoding="utf-8")
            comps = services.discover_services(root, [root / "app.py"])
        self.assertIn("https://llm.internal.example:8443", {c.name for c in comps})


class ReadOnceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _count_reads(self):
        reads: Counter = Counter()
        real = pathlib.Path.read_bytes

        def counting(path):
            reads[Path(path).name] += 1
            return real(path)

        return reads, mock.patch.object(pathlib.Path, "read_bytes", counting)

    def test_a_scan_reads_each_file_once(self):
        (self.root / "app.py").write_text(
            'import openai\nclient = openai.OpenAI(base_url="https://api.openai.com/v1")\n'
            'model = "meta-llama/Llama-3.1-8B"\n', encoding="utf-8")
        (self.root / "README.md").write_text("# demo\nUses gpt-4o.\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("openai==1.40.0\n", encoding="utf-8")
        reads, patch = self._count_reads()
        with patch:
            result = scanner.run_scan(scanner.ScanOptions(target=self.root, offline=True))
        self.assertTrue(any(c.name == "openai" for c in result.components))
        self.assertEqual(reads["app.py"], 1, reads)
        self.assertEqual(reads["README.md"], 1, reads)

    def test_size_limit_still_applies_to_a_remembered_file(self):
        p = self.root / "big.txt"
        p.write_text("x" * 100, encoding="utf-8")
        with textio.read_once():
            self.assertEqual(len(textio.read_text(p, max_bytes=1000)), 100)
            with self.assertRaises(textio.TooLarge):
                textio.read_text(p, max_bytes=10)
        with textio.read_once():
            with self.assertRaises(textio.TooLarge):
                textio.read_text(p, max_bytes=10)
            self.assertEqual(len(textio.read_text(p, max_bytes=1000)), 100)

    def test_nothing_is_remembered_outside_a_scan(self):
        p = self.root / "a.txt"
        p.write_text("one", encoding="utf-8")
        with textio.read_once():
            self.assertEqual(textio.read_text(p), "one")
        p.write_text("two", encoding="utf-8")
        self.assertEqual(textio.read_text(p), "two")
        p.write_text("three", encoding="utf-8")
        self.assertEqual(textio.read_text(p), "three")

    def test_the_memory_budget_is_respected(self):
        for i in range(5):
            (self.root / f"f{i}.txt").write_text("y" * 100, encoding="utf-8")
        reads, patch = self._count_reads()
        with patch, textio.read_once(budget=250):
            for _ in range(2):
                for i in range(5):
                    self.assertEqual(textio.read_text(self.root / f"f{i}.txt"), "y" * 100)
        self.assertEqual(sum(reads.values()), 5 + 3)  # two files fit the budget; three are read twice


class _FailingReader(io.BytesIO):
    """Gives `good` bytes, then fails the way a disk or network share can mid-file."""

    def __init__(self, good: bytes):
        super().__init__(good)
        self.left = len(good)

    def read(self, n=-1):
        if self.left <= 0:
            raise OSError("device went away")
        chunk = super().read(n)
        self.left -= len(chunk)
        return chunk

    def readinto(self, b):
        if self.left <= 0:
            raise OSError("device went away")
        n = super().readinto(b)
        self.left -= n
        return n


class ModelDigestTests(unittest.TestCase):
    """A model file is hashed in one read (SHA-256 for the report and both for known-bad lookups)."""

    def test_digests_match_hashlib_at_every_chunk_boundary(self):
        c = modelfiles._DIGEST_CHUNK
        for size in (0, 1, c - 1, c, c + 1, 3 * c + 5):
            with self.subTest(size=size):
                blob = bytes((i * 7 + size) % 251 for i in range(size))
                want = (hashlib.sha256(blob).hexdigest(), hashlib.sha1(blob).hexdigest())
                self.assertEqual(modelfiles._digests(io.BytesIO(blob)), want)

    def test_a_reader_that_returns_short_reads_is_hashed_to_the_end(self):
        class Trickle(io.BytesIO):
            def read(self, n=-1):
                return super().read(1000 if n < 0 else min(n, 1000))

        blob = bytes(range(256)) * 5000
        self.assertEqual(modelfiles._digests(Trickle(blob)),
                         (hashlib.sha256(blob).hexdigest(), hashlib.sha1(blob).hexdigest()))

    def test_a_read_error_mid_file_is_raised_not_hashed_over(self):
        with self.assertRaises(OSError):
            modelfiles._digests(_FailingReader(b"x" * (3 * modelfiles._DIGEST_CHUNK)))  # fails on the threaded path


if __name__ == "__main__":
    unittest.main()
