"""The terms of redistributed OSV records (design doc 13 H.3): each record's id prefix names its
database; only records from databases whose licence allows redistribution are bundled."""

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

TOOLS = Path(__file__).resolve().parents[1] / "tools"
DATA = Path(__file__).resolve().parents[1] / "src" / "aiterprise_scan" / "data" / "ait"


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


osv_terms = load_tool("osv_terms")


def advisory(vid, name="transformers", eco="PyPI"):
    return {"id": vid, "aliases": [], "summary": f"issue in {name}",
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0"}]}]}]}


class TermsTests(unittest.TestCase):
    def test_known_sources_and_their_licences(self):
        self.assertEqual(osv_terms.terms("GHSA-xxxx-yyyy-zzzz"),
                         {"prefix": "GHSA", "source": "GitHub Advisory Database", "licence": "CC-BY-4.0",
                          "url": "https://github.com/github/advisory-database"})
        self.assertEqual(osv_terms.terms("PYSEC-2024-1")["licence"], "CC-BY-4.0")
        self.assertEqual(osv_terms.terms("MAL-2026-2144")["licence"], "Apache-2.0")

    def test_unknown_or_restricted_sources_are_not_redistributable(self):
        # Chainguard's records are CC-BY-NC-ND, Ubuntu's CC-BY-SA; an unknown prefix was never checked
        for vid in ("CGA-1234-abcd", "UBUNTU-CVE-2024-1", "FOO-1", "GHSA", ""):
            self.assertIsNone(osv_terms.terms(vid), vid)

    def test_a_listed_database_whose_licence_forbids_it_is_still_left_out(self):
        chainguard = {"source": "Chainguard", "licence": "CC-BY-NC-ND-4.0", "url": "https://example.invalid"}
        with mock.patch.dict(osv_terms.SOURCES, {"CGA": chainguard}):
            self.assertIsNone(osv_terms.terms("CGA-1234-abcd"))
            self.assertEqual(osv_terms.summarise(["CGA-1234-abcd"]), ([], {"CGA": 1}))

    def test_a_summary_counts_records_per_source(self):
        kept, excluded = osv_terms.summarise(["GHSA-a", "GHSA-b", "PYSEC-1", "CGA-x", "FOO-1", "FOO-2", "GHSA-a"])
        self.assertEqual([(t["prefix"], t["records"]) for t in kept], [("GHSA", 2), ("PYSEC", 1)])
        self.assertEqual(excluded, {"CGA": 1, "FOO": 2})

    def test_terms_are_listed_in_prefix_order_whatever_order_the_ids_came_in(self):
        fake = {p: {"source": p, "licence": "Apache-2.0", "url": "https://example.invalid"} for p in "ABCDEF"}
        with mock.patch.dict(osv_terms.SOURCES, fake):
            kept, _ = osv_terms.summarise([f"{p}-1" for p in "FDBECA"])
        self.assertEqual([t["prefix"] for t in kept], list("ABCDEF"))


class VulnSubsetBuilderTests(unittest.TestCase):
    def test_records_from_unlisted_sources_are_left_out_and_named(self):
        builder = load_tool("build_vuln_subset")
        docs = [advisory("GHSA-keep-keep-keep"), advisory("PYSEC-2024-9"), advisory("CGA-xxxx-yyyy"),
                advisory("FOO-2024-1"),
                # npm records inside a PyPI export: npm is not covered, so they count nowhere
                advisory("GHSA-npm1-npm1-npm1", name="openai", eco="npm"), advisory("CGA-npm", name="openai", eco="npm")]
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "PyPI-all.zip"
            with zipfile.ZipFile(z, "w") as zf:
                for d in docs:
                    zf.writestr(f"{d['id']}.json", json.dumps(d))
            out = Path(tmp) / "vuln-subset.json.gz"
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                builder.main(["--zip", str(z), "--out", str(out)])
            built = json.loads(gzip.decompress(out.read_bytes()))
        self.assertEqual([d["id"] for d in built["packages"]["pypi"]["transformers"]],
                         ["GHSA-keep-keep-keep", "PYSEC-2024-9"])
        self.assertEqual([(t["prefix"], t["licence"], t["records"]) for t in built["terms"]],
                         [("GHSA", "CC-BY-4.0", 1), ("PYSEC", "CC-BY-4.0", 1)])
        self.assertEqual(built["excluded"], {"CGA": 1, "FOO": 1})
        self.assertEqual(built["advisory_count"], 2)
        self.assertIn("left out 2 advisories", printed.getvalue())
        self.assertIn("CGA 1", printed.getvalue())


class MaliciousBuilderTests(unittest.TestCase):
    def test_the_snapshot_names_its_source_and_licence(self):
        builder = load_tool("build_malicious")
        doc = advisory("MAL-2026-1", name="evil")
        doc["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}]
        built = json.loads(gzip.decompress(builder.encode(builder.records_from_osv(doc), [])))
        self.assertEqual(built["terms"], [{"prefix": "MAL", "source": "OpenSSF Malicious Packages",
                                           "licence": "Apache-2.0", "url": "https://github.com/ossf/malicious-packages",
                                           "records": 1}])
        self.assertEqual(built["excluded"], {})

    def test_a_record_from_an_unlisted_source_is_refused(self):
        builder = load_tool("build_malicious")
        rec = {"id": "XYZ-1", "ecosystem": "pypi", "name": "evil", "versions": ["1.0"], "all_versions": False,
               "published": None, "aliases": [], "withdrawn": None}
        built = json.loads(gzip.decompress(builder.encode([rec], [])))
        self.assertEqual(built["packages"], {})
        self.assertEqual(built["excluded"], {"XYZ": 1})


class ShippedDataTests(unittest.TestCase):
    """The per-record check on what the wheel carries: every record's source allows redistribution."""

    def ids(self, path, sections):
        doc = json.loads(gzip.decompress(path.read_bytes()))
        for section in sections:
            for names in (doc.get(section) or {}).values():
                for entries in names.values():
                    for entry in entries:
                        yield entry["id"] if isinstance(entry, dict) else entry[0]

    def test_every_bundled_advisory_may_be_redistributed(self):
        ids = list(self.ids(DATA / "vuln-subset.json.gz", ["packages"]))
        self.assertGreater(len(ids), 1000)
        _, excluded = osv_terms.summarise(ids)
        self.assertEqual(excluded, {})

    def test_every_bundled_malicious_record_may_be_redistributed(self):
        ids = list(self.ids(DATA / "malicious-versions.json.gz", ["packages", "withdrawn"]))
        self.assertGreater(len(ids), 100000)
        _, excluded = osv_terms.summarise(ids)
        self.assertEqual(excluded, {})


if __name__ == "__main__":
    unittest.main()
