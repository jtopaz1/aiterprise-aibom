"""Core: model, versions, YAML subset, tolerant text I/O, purl, walker."""

import codecs
import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import miniyaml, purl, textio, versions
from aiterprise_scan.model import Component, Evidence, Finding, Location, merge_components, severity_at_least
from aiterprise_scan.walk import walk


class ModelTests(unittest.TestCase):
    def test_purl_forms(self):
        self.assertEqual(Component("Foo_Bar", ecosystem="pypi", version="1.0").purl, "pkg:pypi/foo-bar@1.0")
        self.assertEqual(Component("@anthropic-ai/sdk", ecosystem="npm", version="0.27.0").purl,
                         "pkg:npm/%40anthropic-ai/sdk@0.27.0")
        self.assertEqual(Component("meta-llama/Meta-Llama-3-8B", ctype="model", ecosystem="huggingface").purl,
                         "pkg:huggingface/meta-llama/Meta-Llama-3-8B")
        self.assertIsNone(Component("weights.pt", ctype="model-file").purl)

    def test_fingerprint_ignores_line_numbers(self):
        c = Component("litellm", ecosystem="pypi", version="1.82.7")
        a = Finding("ait.pkg.malicious", "t", "critical", component=c, location=Location("requirements.txt", 3),
                    advisory_id="MAL-2026-2144")
        b = Finding("ait.pkg.malicious", "t", "critical", component=c, location=Location("requirements.txt", 9),
                    advisory_id="MAL-2026-2144")
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertEqual(len(a.fingerprint), 16)
        other = Finding("ait.pkg.malicious", "t", "critical", component=c, location=Location("other.txt", 3),
                        advisory_id="MAL-2026-2144")
        self.assertNotEqual(a.fingerprint, other.fingerprint)

    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            Finding("x", "t", "severe")

    def test_merge_keeps_locations(self):
        a = Component("openai", ecosystem="pypi", version="1.0", locations=[Location("a.txt", 1)])
        b = Component("OpenAI", ecosystem="pypi", version="1.0", locations=[Location("b.txt", 2)], licence="MIT")
        merged = merge_components([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual([str(l) for l in merged[0].locations], ["a.txt:1", "b.txt:2"])
        self.assertEqual(merged[0].licence, "MIT")

    def test_severity_order(self):
        self.assertTrue(severity_at_least("critical", "high"))
        self.assertFalse(severity_at_least("low", "medium"))

    def test_evidence_dict(self):
        e = Evidence("osv", "GHSA-x", "https://osv.dev", {"published": "2026"})
        self.assertEqual(e.to_dict()["published"], "2026")


class VersionTests(unittest.TestCase):
    def test_pep440_ordering(self):
        order = ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0.post1", "1.1"]
        keys = [versions.pep440_parse(v) for v in order]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(versions.pep440_parse("1.82.07"), versions.pep440_parse("1.82.7"))
        self.assertEqual(versions.pep440_parse("1.0"), versions.pep440_parse("1.0.0"))

    def test_pypi_specifiers(self):
        c = versions.pypi_spec_contains
        self.assertTrue(c(">=1.80,<1.90", "1.82.7"))
        self.assertFalse(c(">=1.83", "1.82.7"))
        self.assertTrue(c("~=1.82.0", "1.82.8"))
        self.assertFalse(c("~=1.82.0", "1.83.0"))
        self.assertTrue(c("==1.82.*", "1.82.7"))
        self.assertFalse(c("!=1.82.7", "1.82.7"))
        self.assertTrue(c("", "1.0"))
        self.assertIsNone(c("@@nonsense", "1.0"))

    def test_npm_ranges(self):
        c = versions.npm_range_contains
        self.assertTrue(c("^1.14.0", "1.14.1"))
        self.assertFalse(c("^1.15.0", "1.14.1"))
        self.assertTrue(c("~0.30.0", "0.30.4"))
        self.assertFalse(c("^0.29.0", "0.30.4"))
        self.assertTrue(c("1.x", "1.14.1"))
        self.assertTrue(c(">=1.0.0 <2.0.0", "1.14.1"))
        self.assertTrue(c(">= 1.0.0 < 2.0.0", "1.14.1"))
        self.assertFalse(c(">=1.0.0 <1.14.1", "1.14.1"))
        self.assertTrue(c("1.0.0 - 1.20.0", "1.14.1"))
        self.assertTrue(c("^2.0.0 || ^1.14.0", "1.14.1"))
        self.assertFalse(c("1.14.0", "1.14.1"))
        self.assertTrue(c("*", "1.14.1"))
        self.assertIsNone(c("github:axios/axios", "1.14.1"))
        self.assertFalse(c("^1.14.1", "1.15.0-beta.1") and False)


class MiniYamlTests(unittest.TestCase):
    def test_policy_shape(self):
        doc = miniyaml.load(
            "version: 1\nfail_on: [critical, high]   # gate\nsuppressions:\n"
            "  - finding: abc\n    until: 2027-06-30\n    reason: \"vendor # patch\"\n"
        )
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["fail_on"], ["critical", "high"])
        self.assertEqual(doc["suppressions"][0]["until"], "2027-06-30")
        self.assertEqual(doc["suppressions"][0]["reason"], "vendor # patch")

    def test_versions_stay_strings(self):
        self.assertEqual(miniyaml.load("v: 1.10\nn: 7")["v"], "1.10")
        self.assertEqual(miniyaml.load("n: 7", typed=False)["n"], "7")

    def test_flow_and_quoted_keys(self):
        doc = miniyaml.load("'@scope/pkg@1.0.0':\n  resolution: {integrity: sha512-x==, tarball: 'https://a/b'}\n")
        self.assertEqual(doc["@scope/pkg@1.0.0"]["resolution"]["tarball"], "https://a/b")

    def test_block_scalar_keeps_hash(self):
        doc = miniyaml.load("note: |\n  # kept\n  two\nafter: x\n")
        self.assertEqual(doc["note"], "# kept\ntwo\n")
        self.assertEqual(doc["after"], "x")

    def test_bad_indentation_raises(self):
        with self.assertRaises(miniyaml.YAMLError):
            miniyaml.load("a: 1\n   b: 2\n")


class TextIOTests(unittest.TestCase):
    def test_utf16_bom(self):
        raw = codecs.BOM_UTF16_LE + '{"a": "é"}'.encode("utf-16-le")
        self.assertEqual(textio.loads_json(textio.decode_bytes(raw)), {"a": "é"})

    def test_utf8_bom(self):
        self.assertEqual(textio.decode_bytes(codecs.BOM_UTF8 + b"x=1"), "x=1")

    def test_jsonc(self):
        text = '{\n  // comment\n  "a": "http://x//y", /* block */\n  "b": [1, 2,],\n}\n'
        self.assertEqual(textio.loads_jsonc(text), {"a": "http://x//y", "b": [1, 2]})


class PurlTests(unittest.TestCase):
    def test_parse(self):
        p = purl.parse("pkg:npm/%40anthropic-ai/sdk@0.27.0")
        self.assertEqual((p.full_name, p.version, p.ecosystem), ("@anthropic-ai/sdk", "0.27.0", "npm"))
        p = purl.parse("pkg:pypi/LiteLLM@1.82.7?extra=x")
        self.assertEqual((p.name, p.version), ("litellm", "1.82.7"))
        p = purl.parse("pkg:huggingface/meta-llama/Meta-Llama-3-8B@abc123")
        self.assertEqual((p.full_name, p.version), ("meta-llama/Meta-Llama-3-8B", "abc123"))
        self.assertIsNone(purl.parse("not-a-purl"))


class WalkTests(unittest.TestCase):
    def test_gitignore_and_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text("*.log\nbuild/\n!keep.log\n")
            for rel in ["a.py", "x.log", "keep.log", "build/out.txt", "node_modules/p/index.js", "src/b.py"]:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x")
            rels = sorted(p.relative_to(root).as_posix() for p in walk(root))
            self.assertEqual(rels, [".gitignore", "a.py", "keep.log", "src/b.py"])
            all_rels = sorted(p.relative_to(root).as_posix() for p in walk(root, all_files=True))
            self.assertIn("x.log", all_rels)
            self.assertNotIn("node_modules/p/index.js", all_rels)


if __name__ == "__main__":
    unittest.main()
