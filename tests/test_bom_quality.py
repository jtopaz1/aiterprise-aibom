"""Finding quality / examined metadata (§4.3) and the annotated CycloneDX AI-BOM (§4.4)."""

import json
import unittest
from unittest import mock

from aiterprise_scan import bom, ingest, quality, report
from aiterprise_scan.model import Component, Evidence, Examined, Finding, Location, ScanResult


def model_file():
    return Component("model.pt", ctype="model-file", locations=[Location("model.pt")], source="file",
                     hashes={"sha256": "ab" * 32}, properties={"path": "model.pt", "format": "pytorch-zip",
                                                               "size": 1234, "pickle_globals": ["os.system"]})


def hf_model():
    return Component("meta-llama/Meta-Llama-3-8B", ctype="model", ecosystem="huggingface", licence="llama3",
                     locations=[Location("app.py", 2)], source="code-ref")


def result_with(findings, comps):
    r = ScanResult("repo", "offline")
    r.components = comps
    r.findings = findings
    r.examined = {"ait-malicious": Examined("ait-malicious", 3, 1), "osv": Examined("osv", skipped="offline"),
                  "osv-subset": Examined("osv-subset", 2, 1), "model-files": Examined("model-files", 1, 1)}
    return r


class QualityTests(unittest.TestCase):
    def test_unmeasured_rule_says_so(self):
        q = quality.rule_quality("ait.mcp.desc.hidden-instructions")
        self.assertEqual(q, {"fp_rate_measured": None, "corpus": None, "evaluated_at": None})

    def test_model_rule_quality_comes_from_its_rule_file(self):
        q = quality.rule_quality("ait.model.pickle.dangerous-global")
        self.assertIn("fp_rate_measured", q)

    def test_measured_value_wins(self):
        measured = {"rules": {"ait.pkg.typosquat": {"fp_rate_measured": 0.02, "corpus": "clean-ai-repos-v1",
                                                    "evaluated_at": "2026-11-14", "findings": 3, "targets": 150}}}
        with mock.patch.object(quality, "_measured", return_value=measured["rules"]):
            q = quality.rule_quality("ait.pkg.typosquat")
        self.assertEqual((q["fp_rate_measured"], q["corpus"], q["targets"]), (0.02, "clean-ai-repos-v1", 150))

    def test_json_report_carries_quality_and_examined(self):
        lit = Component("litellm", ecosystem="pypi", version="1.82.7", locations=[Location("requirements.txt", 1)])
        f = Finding("ait.pkg.malicious", "bad", "critical", "malicious", 98, lit,
                    evidence=[Evidence("ait-malicious", "MAL-1"), Evidence("osv-subset", "PYSEC-1")])
        doc = json.loads(report.dumps_json(result_with([f], [lit])))
        got = doc["findings"][0]
        self.assertEqual(got["quality"]["fp_rate_measured"], None)
        # sources consulted for package judgements (osv was skipped offline), and how many had data
        self.assertEqual(got["examined"], {"sources": 2, "with_data": 2, "skipped": ["osv"]})


class AnnotatedBomTests(unittest.TestCase):
    def test_model_file_gets_a_model_card_with_its_findings(self):
        comp = model_file()
        f = Finding("ait.model.pickle.dangerous-global", "Pickle calls os.system", "critical", "malicious", 95, comp)
        doc = bom.build(result_with([f], [comp]))
        card = doc["components"][0]["modelCard"]
        self.assertEqual(doc["components"][0]["type"], "machine-learning-model")
        limits = card["considerations"]["technicalLimitations"]
        self.assertTrue(any("os.system" in x for x in limits), limits)
        props = {p["name"]: p["value"] for p in card["properties"]}
        self.assertEqual(props["aiterprise:format"], "pytorch-zip")
        self.assertEqual(props["aiterprise:serialisation"], "code-capable (pickle)")

    def test_licence_verdict_rides_in_licenses(self):
        comp = hf_model()
        f = Finding("ait.licence.conditional", "Llama 3 licence: >700M MAU needs a separate licence", "medium",
                    "suspicious", 80, comp,
                    evidence=[Evidence("ait-licence", "llama3", "https://llama.meta.com/llama3/license/",
                                       {"use_context": "commercial"})])
        doc = bom.build(result_with([f], [comp]))
        lics = doc["components"][0]["licenses"]
        self.assertEqual(lics[0], {"license": {"name": "llama3", "acknowledgement": "declared"}})
        verdict = lics[1]["license"]
        self.assertEqual(verdict["name"], "LicenseRef-AIterprise-Verdict-conditional")
        self.assertEqual(verdict["acknowledgement"], "concluded")
        self.assertEqual(verdict["url"], "https://llama.meta.com/llama3/license/")
        props = {p["name"]: p["value"] for p in verdict["properties"]}
        self.assertEqual(props["aiterprise:advisory"], "not legal advice")
        self.assertEqual(props["aiterprise:use_context"], "commercial")
        self.assertIn("modelCard", doc["components"][0])

    def test_annotated_bom_reingests_with_the_declared_licence_only(self):
        comp = hf_model()
        f = Finding("ait.licence.conditional", "Llama 3 licence", "medium", "suspicious", 80, comp,
                    evidence=[Evidence("ait-licence", "llama3")])
        text = json.dumps(bom.build(result_with([f], [comp]), "1.6"))
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.cdx.json"
            p.write_text(text, encoding="utf-8")
            _, comps = ingest.ingest_file(p, None)
        self.assertEqual([c.licence for c in comps if c.ctype == "model"], ["llama3"])


if __name__ == "__main__":
    unittest.main()
