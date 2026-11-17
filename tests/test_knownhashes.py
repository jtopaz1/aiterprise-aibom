"""Known-bad model hashes (design doc 13 C23, the MVP seed list).

A model file whose SHA-256 or SHA-1 is in `data/ait/known-bad-hashes.json` is reported, with the
public report that named it. The check runs on the bytes, before and apart from format sniffing:
the payloads seen in incidents are often not valid models at all (an ELF named `syscore.bin`, a
7z archive named like a PyTorch file).
"""

from __future__ import annotations

import hashlib
import pickle
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from aiterprise_scan import data, knownhashes, modelfiles, sources
from aiterprise_scan.cache import Cache
from aiterprise_scan.scanner import ScanOptions, run_scan

RULE = "ait.model.known-bad-hash"
PAYLOAD = b"\x7fELF\x02\x01\x01 stand-in for a payload that sniffs as no model format"
REPORT = "https://example.test/reports/load-mine"


def listed(**hashes: str):
    """Replace the shipped list with one entry carrying `hashes`."""
    entry = {"file": "syscore.bin", "kind": "elf-payload", "repository": "someone/qwen2-tiny",
             "incident": "Test campaign", "source": "Test Lab", "reported": "2026-10-29", "url": REPORT, **hashes}
    index = knownhashes.build_index({"version": "test", "entries": [entry]})
    return mock.patch.object(knownhashes, "_index", return_value=index)


class SeedListTest(unittest.TestCase):
    def test_every_entry_names_its_hash_report_and_date(self):
        doc = data.load("known-bad-hashes.json")
        self.assertTrue(doc["version"])
        entries = doc["entries"]
        self.assertGreaterEqual(len(entries), 11)
        seen: set[str] = set()
        for e in entries:
            with self.subTest(entry=e.get("sha256") or e.get("sha1")):
                self.assertTrue(e.get("sha256") or e.get("sha1"))
                if "sha256" in e:
                    self.assertRegex(e["sha256"], r"^[0-9a-f]{64}$")
                if "sha1" in e:
                    self.assertRegex(e["sha1"], r"^[0-9a-f]{40}$")
                for h in (e.get("sha256"), e.get("sha1")):
                    if h:
                        self.assertNotIn(h, seen)
                        seen.add(h)
                self.assertTrue(e["url"].startswith("https://"))
                date.fromisoformat(e["reported"])
                self.assertTrue(e["incident"] and e["source"] and e["kind"])
                # An entry for a file the scanner never hashes would be a promise it does not keep.
                if e.get("file"):
                    self.assertTrue(modelfiles.is_model_candidate(Path(e["file"])), e["file"])

    def test_the_rule_is_counted_under_model_files(self):
        self.assertIn(sources.MODEL_FILES.name, sources.for_rule(RULE))


class MatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def scan(self, name: str, payload: bytes):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return modelfiles.analyze_model_file(path, self.root)

    def test_a_listed_sha256_is_reported_though_the_file_sniffs_as_no_model(self):
        self.assertEqual(self.scan("syscore.bin", PAYLOAD), (None, []))  # not listed: not a model
        with listed(sha256=hashlib.sha256(PAYLOAD).hexdigest()):
            comp, findings = self.scan("syscore.bin", PAYLOAD)
        self.assertEqual(comp.ctype, "model-file")
        self.assertEqual(comp.hashes, {"sha256": hashlib.sha256(PAYLOAD).hexdigest()})
        hits = [f for f in findings if f.rule_id == RULE]
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual((f.severity, f.verdict), ("high", "malicious"))
        self.assertIn("Test campaign", f.title)
        ev = f.evidence[0]
        self.assertEqual(ev.url, REPORT)
        self.assertEqual(ev.detail["sha256"], hashlib.sha256(PAYLOAD).hexdigest())
        self.assertEqual(ev.detail["source"], "Test Lab")
        self.assertEqual(ev.detail["reported"], "2026-10-29")
        self.assertEqual(ev.detail["repository"], "someone/qwen2-tiny")

    def test_a_listed_sha1_is_matched(self):
        payload = pickle.dumps({"weights": [1, 2, 3]}, protocol=2)
        with listed(sha1=hashlib.sha1(payload).hexdigest()):
            _comp, findings = self.scan("data.pkl", payload)
        rules = sorted(f.rule_id for f in findings)
        self.assertEqual(rules, [RULE, "ait.model.pickle.format"])
        hit = next(f for f in findings if f.rule_id == RULE)
        self.assertEqual(hit.evidence[0].detail["sha1"], hashlib.sha1(payload).hexdigest())
        self.assertNotIn("sha256", hit.evidence[0].detail)

    def test_an_unlisted_model_gets_no_known_bad_finding(self):
        payload = pickle.dumps({"weights": [1, 2, 3]}, protocol=2)
        with listed(sha256="0" * 64, sha1="0" * 40):
            _comp, findings = self.scan("data.pkl", payload)
        self.assertNotIn(RULE, [f.rule_id for f in findings])

    def test_a_match_is_reported_when_the_analysis_fails(self):
        with listed(sha256=hashlib.sha256(PAYLOAD).hexdigest()), \
                mock.patch.object(modelfiles, "_analyze", side_effect=RuntimeError("boom")):
            comp, findings = self.scan("syscore.bin", PAYLOAD)
        self.assertIsNotNone(comp)
        self.assertIn(RULE, [f.rule_id for f in findings])

    def test_a_scan_reports_the_match_and_counts_the_file(self):
        (self.root / "models").mkdir()
        (self.root / "models" / "syscore.bin").write_bytes(PAYLOAD)
        with listed(sha256=hashlib.sha256(PAYLOAD).hexdigest()):
            result = run_scan(ScanOptions(target=self.root, offline=True, cache=Cache(enabled=False)))
        self.assertIn(RULE, [f.rule_id for f in result.findings])
        examined = result.examined[sources.MODEL_FILES.name]
        self.assertEqual((examined.checked, examined.with_data), (1, 1))


if __name__ == "__main__":
    unittest.main()
