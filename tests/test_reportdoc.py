"""The report document: the JSON form of a scan's result, and the copy of it that may leave the machine."""

import copy
import json
import unittest

from aiterprise_scan import reportdoc
from aiterprise_scan.model import Component, Evidence, Examined, Finding, Location, ScanResult

PROJECT = "C:\\Users\\someone\\work\\demo-repo"


def scan_result(with_provider=True):
    """A result with one finding of each kind that matters here; `with_provider` adds what a
    `--byo virustotal=…` scan adds: a finding, a coverage entry and a note."""
    lib = Component("litellm", ecosystem="pypi", version="1.82.7", locations=[Location("requirements.txt", 1)])
    model = Component("model.pt", ctype="model-file", locations=[Location(PROJECT + "\\model.pt")], source="file",
                      hashes={"sha256": "ab" * 32})
    result = ScanResult(target=PROJECT, mode="online", started_at="2026-11-16T00:00:00Z")
    result.files_walked = 7
    result.components = [lib, model]
    result.findings = [
        Finding("ait.pkg.malicious", "Known-malicious package version", "critical", "malicious", 98, lib,
                evidence=[Evidence("ait-malicious", "MAL-1")]),
        Finding("ait.model.pickle.format", "Pickle model file", "medium", "suspicious", 80, model),
        Finding("ait.secret.openai", "An API key in a config", "low", "suspicious", 70, status="suppressed",
                location=Location(PROJECT + "\\.env", 3)),
    ]
    result.examined = {"ait-malicious": Examined("ait-malicious", 1, 1), "model-files": Examined("model-files", 1, 1)}
    result.notes = ["walk: stopped at the cap of 200,000 files"]
    result.notices = [{"id": "ntc_1", "text": "Hash data from a third party."}]
    result.exit_code = 1
    if with_provider:
        result.findings.append(Finding("ext.virustotal.malicious", "VirusTotal: 12 engines flag this file", "high",
                                       "suspicious", 90, model, evidence=[Evidence("virustotal", "ab" * 32)]))
        result.examined["virustotal"] = Examined("virustotal", 1, 1)
        result.notes.append("virustotal: 1 file was not verified with VirusTotal (over the lookup budget)")
    return result


class WritingTests(unittest.TestCase):
    def test_the_document_names_its_schema(self):
        self.assertEqual(reportdoc.build(scan_result())["schema"], "aiterprise-report/1")
        self.assertEqual(reportdoc.SCHEMA, "aiterprise-report/1")

    def test_the_key_list_is_exactly_what_is_written(self):
        self.assertEqual(tuple(reportdoc.build(scan_result())), reportdoc.TOP_LEVEL_KEYS)

    def test_the_summary_counts_findings_that_are_still_active(self):
        summary = reportdoc.build(scan_result())["summary"]
        self.assertEqual(summary["findings"], 4)
        self.assertEqual(summary["severity"], {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0})
        self.assertEqual(summary["status"], {"new": 3, "suppressed": 1})
        self.assertEqual((summary["files_walked"], summary["components"]), (7, 2))
        self.assertEqual(summary["components_by_type"], {"library": 1, "model-file": 1})

    def test_the_document_is_plain_json(self):
        doc = reportdoc.build(scan_result())
        self.assertEqual(json.loads(json.dumps(doc)), doc)


class SchemaTests(unittest.TestCase):
    def test_a_document_without_a_schema_is_an_older_report(self):
        reportdoc.check_schema({"findings": []})

    def test_the_current_schema_is_accepted(self):
        reportdoc.check_schema(reportdoc.build(scan_result()))

    def test_another_schema_is_refused_and_both_are_named(self):
        with self.assertRaises(reportdoc.SchemaError) as caught:
            reportdoc.check_schema({"schema": "aiterprise-report/2", "findings": []})
        self.assertIn("aiterprise-report/2", str(caught.exception))
        self.assertIn("aiterprise-report/1", str(caught.exception))


class ProjectNameTests(unittest.TestCase):
    def test_the_project_is_the_last_part_of_the_target(self):
        self.assertEqual(reportdoc.project_name({"target": PROJECT}), "demo-repo")
        self.assertEqual(reportdoc.project_name({"target": "/home/someone/work/repo/"}), "repo")

    def test_a_document_without_a_target_has_the_default_project(self):
        self.assertEqual(reportdoc.project_name({}), "default")


class UploadViewTests(unittest.TestCase):
    def view(self, result):
        return reportdoc.upload_view(reportdoc.build(result))

    def test_no_local_path_is_left(self):
        sent, _ = self.view(scan_result())
        self.assertEqual(sent["target"], "demo-repo")
        self.assertNotIn("someone", json.dumps(sent))
        self.assertIn("requirements.txt", json.dumps(sent))  # a path inside the project stays

    def test_a_home_directory_outside_the_project_becomes_a_tilde(self):
        doc = {"target": PROJECT, "findings": [],
               "components": [{"name": "x", "locations": ["C:\\Users\\someone\\.cursor\\mcp.json"]}]}
        sent, _ = reportdoc.upload_view(doc)
        self.assertEqual(sent["components"][0]["locations"], ["~/.cursor/mcp.json"])

    def test_no_provider_result_is_left_and_the_count_says_what_stayed(self):
        sent, kept_local = self.view(scan_result())
        self.assertEqual(kept_local, {"virustotal": 1})
        self.assertEqual([f["rule_id"] for f in sent["findings"]],
                         ["ait.pkg.malicious", "ait.model.pickle.format", "ait.secret.openai"])
        self.assertNotIn("virustotal", json.dumps(sent).lower())  # the finding, its coverage and its note
        self.assertIn("model-files", sent["examined"])
        self.assertEqual(sent["notes"], ["walk: stopped at the cap of 200,000 files"])

    def test_its_summary_is_the_summary_of_what_remains(self):
        sent, _ = self.view(scan_result())
        self.assertEqual(sent["summary"], reportdoc.build(scan_result(with_provider=False))["summary"])

    def test_a_document_without_provider_results_changes_only_its_paths(self):
        doc = reportdoc.build(scan_result(with_provider=False))
        sent, kept_local = reportdoc.upload_view(doc)
        self.assertEqual(kept_local, {})
        self.assertEqual({key for key in doc if doc[key] != sent[key]}, {"target", "components", "findings"})
        self.assertEqual(sent["summary"], doc["summary"])

    def test_the_callers_document_is_not_changed(self):
        doc = reportdoc.build(scan_result())
        before = copy.deepcopy(doc)
        reportdoc.upload_view(doc)
        self.assertEqual(doc, before)

    def test_applying_it_twice_changes_nothing_more(self):
        once, _ = self.view(scan_result())
        twice, kept_local = reportdoc.upload_view(once)
        self.assertEqual((twice, kept_local), (once, {}))

    def test_a_document_that_is_barely_a_report_passes_through(self):
        self.assertEqual(reportdoc.upload_view({"findings": []}), ({"findings": []}, {}))


if __name__ == "__main__":
    unittest.main()
