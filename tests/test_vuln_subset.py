"""Offline vulnerability judgement from the bundled AI-package advisory subset (design doc 13 §5.3)."""

import contextlib
import gzip
import importlib.util
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from aiterprise_scan import net, vulns
from aiterprise_scan.cache import Cache
from aiterprise_scan.model import Component, Location, ScanResult


def lib(name, version, eco="pypi"):
    return Component(name, ecosystem=eco, version=version, locations=[Location("requirements.txt", 1)],
                     source="lockfile")


def doc(vid, name, eco="PyPI", events=None, versions=None, rtype="ECOSYSTEM", **extra):
    aff = {"package": {"ecosystem": eco, "name": name}}
    if events is not None:
        aff["ranges"] = [{"type": rtype, "events": events}]
    if versions is not None:
        aff["versions"] = versions
    return {"id": vid, "aliases": [], "summary": f"issue in {name}", "affected": [aff], **extra}


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class OsvAffectsTests(unittest.TestCase):
    def test_introduced_and_fixed(self):
        d = doc("GHSA-1", "transformers", events=[{"introduced": "0"}, {"fixed": "4.48.0"}])
        self.assertIs(vulns.osv_affects(d, lib("transformers", "4.44.0")), True)
        self.assertIs(vulns.osv_affects(d, lib("transformers", "4.48.0")), False)
        self.assertIs(vulns.osv_affects(d, lib("transformers", "4.50.1")), False)

    def test_last_affected_is_inclusive(self):
        d = doc("GHSA-2", "torch", events=[{"introduced": "1.0"}, {"last_affected": "1.2"}])
        self.assertIs(vulns.osv_affects(d, lib("torch", "1.2")), True)
        self.assertIs(vulns.osv_affects(d, lib("torch", "1.2.1")), False)
        self.assertIs(vulns.osv_affects(d, lib("torch", "0.9")), False)

    def test_two_intervals(self):
        d = doc("GHSA-3", "gradio", events=[{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"},
                                           {"fixed": "2.3"}])
        self.assertIs(vulns.osv_affects(d, lib("gradio", "1.7")), False)
        self.assertIs(vulns.osv_affects(d, lib("gradio", "2.1")), True)

    def test_explicit_version_list(self):
        d = doc("PYSEC-1", "langchain", versions=["0.0.1", "0.0.2"])
        self.assertIs(vulns.osv_affects(d, lib("langchain", "0.0.2")), True)
        self.assertIs(vulns.osv_affects(d, lib("langchain", "0.0.3")), False)

    def test_npm_semver_range(self):
        d = doc("GHSA-4", "@langchain/core", eco="npm", rtype="SEMVER",
                events=[{"introduced": "0"}, {"fixed": "0.3.5"}])
        self.assertIs(vulns.osv_affects(d, lib("@langchain/core", "0.3.4", "npm")), True)
        self.assertIs(vulns.osv_affects(d, lib("@langchain/core", "0.3.5", "npm")), False)

    def test_entry_for_another_package_is_ignored(self):
        d = doc("GHSA-5", "tensorflow-gpu", events=[{"introduced": "0"}])
        self.assertIs(vulns.osv_affects(d, lib("tensorflow", "2.0.0")), False)

    def test_unparseable_version_is_undecided(self):
        d = doc("GHSA-6", "transformers", events=[{"introduced": "0"}, {"fixed": "4.48.0"}])
        self.assertIsNone(vulns.osv_affects(d, lib("transformers", "not-a-version")))


class OfflineClient(vulns.OSVClient):
    def __init__(self):
        super().__init__(cache=Cache(enabled=False), offline=True)


FAKE_SUBSET = {
    "schema": "ait-vuln-subset/1", "generated_at": "2026-11-14T00:00:00Z", "package_count": 1,
    "advisory_count": 1,
    "packages": {"pypi": {"transformers": [
        doc("GHSA-aaaa-bbbb-cccc", "transformers", events=[{"introduced": "0"}, {"fixed": "4.48.0"}],
            aliases=["CVE-2024-11392"], database_specific={"severity": "HIGH"}),
    ]}},
}


class OfflineSubsetTests(unittest.TestCase):
    def test_offline_scan_judges_ai_package_from_subset(self):
        result = ScanResult("t", "offline")
        with mock.patch.object(vulns, "vuln_subset", return_value=FAKE_SUBSET):
            fs = vulns.judge([lib("transformers", "4.44.0")], result, OfflineClient())
        self.assertEqual([(f.rule_id, f.advisory_id, f.severity) for f in fs],
                         [("ait.vuln.advisory", "GHSA-aaaa-bbbb-cccc", "high")])
        self.assertIn("4.48.0", fs[0].remediation)
        self.assertEqual(fs[0].evidence[0].source, "osv-subset")
        ex = result.examined["osv-subset"]
        self.assertEqual((ex.checked, ex.with_data), (1, 1))

    def test_fixed_version_has_no_finding_but_was_checked(self):
        result = ScanResult("t", "offline")
        with mock.patch.object(vulns, "vuln_subset", return_value=FAKE_SUBSET):
            fs = vulns.judge([lib("transformers", "4.48.0")], result, OfflineClient())
        self.assertEqual(fs, [])
        self.assertEqual(result.examined["osv-subset"].checked, 1)

    def test_package_outside_the_subset_is_reported_unchecked(self):
        result = ScanResult("t", "offline")
        with mock.patch.object(vulns, "vuln_subset", return_value=FAKE_SUBSET):
            fs = vulns.judge([lib("lodash", "4.17.0", "npm")], result, OfflineClient())
        self.assertEqual(fs, [])
        self.assertTrue(any("not checked" in n and "1 package" in n for n in result.notes), result.notes)

    def test_online_scan_does_not_use_the_subset(self):
        class Online(vulns.OSVClient):
            def query_ids(self, queries, result=None):
                return {q: [] for q in queries}

            def details(self, ids):
                return {}

        result = ScanResult("t", "online")
        with mock.patch.object(vulns, "vuln_subset", return_value=FAKE_SUBSET):
            fs = vulns.judge([lib("transformers", "4.44.0")], result, Online(cache=Cache(enabled=False)))
        self.assertEqual(fs, [])
        self.assertNotIn("osv-subset", result.examined)

    def test_unreachable_osv_falls_back_to_the_subset_and_stays_an_error(self):
        class Down(vulns.OSVClient):
            def query_ids(self, queries, result=None):
                raise net.NetError("POST https://api.osv.dev/v1/querybatch failed: timed out")

        result = ScanResult("t", "online")
        with mock.patch.object(vulns, "vuln_subset", return_value=FAKE_SUBSET):
            fs = vulns.judge([lib("transformers", "4.44.0")], result, Down(cache=Cache(enabled=False)))
        self.assertEqual([f.advisory_id for f in fs], ["GHSA-aaaa-bbbb-cccc"])
        self.assertEqual(result.examined["osv"].errors, 1)

    def test_bundled_subset_knows_transformers_4_44(self):
        result = ScanResult("t", "offline")
        fs = vulns.judge([lib("transformers", "4.44.0")], result, OfflineClient())
        self.assertTrue(any(f.rule_id.startswith("ait.vuln.") for f in fs))
        meta = vulns.vuln_subset()
        self.assertGreater(meta["package_count"], 20)


class BuilderTests(unittest.TestCase):
    def test_build_keeps_ai_packages_only_and_trims(self):
        builder = load_tool("build_vuln_subset")
        keep = doc("GHSA-keep", "transformers", events=[{"introduced": "0"}, {"fixed": "4.48.0"}],
                   versions=["4.0.0", "4.1.0"], details="long text " * 100, references=[{"url": "x"}])
        other = doc("GHSA-other", "left-pad", eco="npm", events=[{"introduced": "0"}])
        mal = doc("MAL-2026-1", "transformers", events=[{"introduced": "0"}])
        gone = doc("GHSA-gone", "transformers", events=[{"introduced": "0"}], withdrawn="2026-01-01T00:00:00Z")
        mal_alias = doc("PYSEC-2026-2", "transformers", events=[{"introduced": "0"}], aliases=["MAL-2026-2144"])
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "PyPI-all.zip"
            with zipfile.ZipFile(z, "w") as zf:
                for d in (keep, other, mal, gone, mal_alias):
                    zf.writestr(f"{d['id']}.json", json.dumps(d))
            out = Path(tmp) / "vuln-subset.json.gz"
            with contextlib.redirect_stdout(io.StringIO()):
                builder.main(["--zip", str(z), "--out", str(out)])
            built = json.loads(gzip.decompress(out.read_bytes()))
        self.assertEqual(built["schema"], "ait-vuln-subset/1")
        docs = built["packages"]["pypi"]["transformers"]
        self.assertEqual([d["id"] for d in docs], ["GHSA-keep"])
        self.assertNotIn("details", docs[0])
        self.assertNotIn("versions", docs[0]["affected"][0])  # ranges already decide
        self.assertNotIn("npm", built["packages"])  # an npm record inside a PyPI export is not coverage
        self.assertEqual(built["packages"]["pypi"]["openai"], [])  # covered, nothing known
        self.assertEqual(built["inputs"][0]["file"], "PyPI-all.zip")

    def test_covered_package_without_advisories_counts_as_checked(self):
        subset = dict(FAKE_SUBSET, packages={"pypi": {"openai": []}})
        result = ScanResult("t", "offline")
        with mock.patch.object(vulns, "vuln_subset", return_value=subset):
            fs = vulns.judge([lib("openai", "1.50.0")], result, OfflineClient())
        self.assertEqual(fs, [])
        self.assertEqual((result.examined["osv-subset"].checked, result.examined["osv-subset"].with_data), (1, 0))
        self.assertFalse(any("not checked" in n for n in result.notes), result.notes)


if __name__ == "__main__":
    unittest.main()
