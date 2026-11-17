"""Malicious snapshot, OSV/KEV judgement (with a fake OSV), policy, BOM ingest/emit, SARIF."""

import datetime as dt
import gzip
import shutil
import importlib.util
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from aiterprise_scan import bom, discover, ingest, intel_malicious, net, report, vulns
from aiterprise_scan import policy as pol
from aiterprise_scan.cache import Cache
from aiterprise_scan.model import Component, Finding, Location, ScanResult, normalize_name
from aiterprise_scan.scanner import ScanOptions, run_scan

GOLDEN = Path(__file__).parent / "golden"


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_malicious", Path(__file__).resolve().parents[1] / "tools" / "build_malicious.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def lib(name, version=None, eco="pypi", spec=None, path="requirements.txt"):
    return Component(name, ecosystem=eco, version=version, version_spec=spec, locations=[Location(path, 1)],
                     source="lockfile" if version else "manifest")


def _reference_index(*sections):
    """intel_malicious._LazyIndex's keys and entries as it built them before: every name, at load."""
    raw = {}
    for packages in sections:
        for eco, names in packages.items():
            for name, entries in names.items():
                raw.setdefault((eco, normalize_name(name, eco)), []).append((eco, name, entries))
    return raw


def _records(entries):
    return [(eco, name, e[0], tuple(e[3]), bool(e[2]), (e[5] or None) if len(e) > 5 else None)
            for eco, name, es in entries for e in es]


class SnapshotIndexTests(unittest.TestCase):
    ACTIVE = {
        "npm": {"Foo": [["MAL-1", "", 0, ["1.0.0"]]], "foo": [["MAL-2", "", 1, []]], "bar": [["MAL-3", "", 0, ["2"]]],
                "Baz": [["MAL-4", "", 0, ["1"]]], "@Scope/Pkg": [["MAL-12", "", 0, ["1"]]]},
        # the exact spelling between two others that normalize to it: records keep the file's order
        "pypi": {"Evil_Pkg": [["MAL-5", "2026-01-02", 0, ["1.0"], ["GHSA-a"]]], "evil-pkg": [["MAL-6", "", 0, ["2.0"]]],
                 "evil.pkg": [["MAL-7", "", 0, ["3.0"]]], "clean": [["MAL-8", "", 0, ["1"]]]},
        "crates.io": {"Odd_Crate": [["MAL-11", "", 0, ["0.1"]]]},
    }
    WITHDRAWN = {"npm": {"foo": [["MAL-9", "", 0, ["1.0.1"], [], "2026-03-01"]]},
                 "pypi": {"Evil_Pkg": [["MAL-10", "", 0, ["4"], [], "2026-03-02"]]}}

    def same(self, idx, ref, keys):
        for key in keys:
            with self.subTest(key=key):
                self.assertIn(key, idx)
                got = [(r.ecosystem, r.name, r.id, r.versions, r.all_versions, r.withdrawn) for r in idx[key]]
                self.assertEqual(got, _records(ref[key]))

    def test_the_index_answers_what_a_full_index_does(self):
        idx = intel_malicious._LazyIndex(self.ACTIVE, self.WITHDRAWN)
        ref = _reference_index(self.ACTIVE, self.WITHDRAWN)
        self.same(idx, ref, list(ref))
        self.assertEqual(list(idx), list(ref))
        self.assertEqual(len(idx), len(ref))
        self.assertEqual([r.id for r in idx[("pypi", "evil-pkg")]], ["MAL-5", "MAL-6", "MAL-7", "MAL-10"])
        self.assertEqual(idx[("pypi", "evil-pkg")][0].aliases, ("GHSA-a",))

    def test_only_normalized_keys_are_found(self):
        idx = intel_malicious._LazyIndex(self.ACTIVE, self.WITHDRAWN)
        for key in [("npm", "Foo"), ("npm", "Baz"), ("pypi", "Evil_Pkg"), ("pypi", "evil.pkg"), ("npm", "nothing"),
                    ("cargo", "foo"), ("crates.io", "odd_crate")]:
            with self.subTest(key=key):
                self.assertNotIn(key, idx)
                self.assertIsNone(idx.get(key))
                with self.assertRaises(KeyError):
                    idx[key]
        self.assertIn(("crates.io", "Odd_Crate"), idx)  # no rule for this ecosystem: the name as it is
        for key in ["foo", ("npm",), ("npm", "foo", "x"), ("npm", None), None]:
            with self.subTest(key=key):
                self.assertNotIn(key, idx)
                with self.assertRaises(KeyError):
                    idx[key]

    def test_the_bundled_snapshot_answers_what_a_full_index_does(self):
        raw = intel_malicious.data.load(intel_malicious.SNAPSHOT_FILE)
        sections = (raw["packages"], raw.get("withdrawn") or {})
        idx = intel_malicious._LazyIndex(*sections)
        ref = _reference_index(*sections)
        keys = list(ref)
        merged = [k for k, v in ref.items() if len(v) > 1 or v[0][1] != k[1]]  # a name unlike its key
        self.assertTrue(merged)
        self.same(idx, ref, merged + keys[::97])
        self.assertEqual(len(idx), len(ref))
        self.assertEqual(list(idx), keys)


class MaliciousSnapshotTests(unittest.TestCase):
    def test_bundled_seed_has_litellm_and_axios(self):
        snap = intel_malicious.load_snapshot()
        self.assertIn(("pypi", "litellm"), snap.records)
        self.assertIn(("npm", "axios"), snap.records)

    def test_exact_range_and_unknown(self):
        result = ScanResult("t", "offline")
        comps = [
            lib("litellm", "1.82.7"),
            lib("LiteLLM", "1.82.6"),
            lib("axios", spec="^1.14.0", eco="npm", path="package.json"),
            lib("litellm", spec=">=1.108", path="other.txt"),  # excludes 1.107.0
            lib("litellm", path="imports.py"),
        ]
        fs = intel_malicious.judge(comps, result)
        rules = sorted(f.rule_id for f in fs)
        self.assertEqual(rules, ["ait.pkg.malicious", "ait.pkg.malicious-range", "ait.pkg.malicious-unpinned"])
        crit = next(f for f in fs if f.rule_id == "ait.pkg.malicious")
        self.assertEqual((crit.severity, crit.verdict, crit.advisory_id), ("critical", "malicious", "MAL-2026-2144"))
        self.assertIn("1.82.8", crit.evidence[0].detail["affected_versions"])
        self.assertEqual(result.examined["ait-malicious"].checked, 5)

    def test_withdrawn_record_reported_as_withdrawn(self):
        # design doc 13 §4.3: findings on withdrawn records flip to `withdrawn`, never silently dropped
        snap = intel_malicious.parse_snapshot({"records": [
            {"id": "MAL-1", "ecosystem": "pypi", "name": "fastapi", "versions": ["0.136.3"], "withdrawn": "2026-10-01"},
        ]})
        result = ScanResult("t", "offline")
        fs = intel_malicious.judge([lib("fastapi", "0.136.3")], result, snapshot=snap)
        self.assertEqual([(f.rule_id, f.advisory_id, f.status) for f in fs],
                         [("ait.pkg.malicious", "MAL-1", "withdrawn")])
        self.assertEqual(fs[0].evidence[0].detail["withdrawn"], "2026-10-01")
        result.findings = fs
        self.assertEqual(pol.apply(result, pol.Policy()), [])
        self.assertEqual(result.severity_counts()["critical"], 0)

    def test_all_versions_record(self):
        snap = intel_malicious.parse_snapshot({"records": [
            {"id": "MAL-2", "ecosystem": "npm", "name": "evil-pkg", "versions": [], "all_versions": True},
        ]})
        fs = intel_malicious.judge([lib("evil-pkg", eco="npm", path="package.json")], snapshot=snap)
        self.assertEqual([f.severity for f in fs], ["critical"])

    def test_v2_builder_round_trip(self):
        builder = load_builder()
        osv = [
            {"id": "MAL-9", "published": "2026-01-02T00:00:00Z", "aliases": ["GHSA-x"],
             "affected": [{"package": {"ecosystem": "PyPI", "name": "Evil_Pkg"}, "versions": ["1.0.1"]}]},
            {"id": "MAL-10", "affected": [{"package": {"ecosystem": "npm", "name": "@scope/spam"},
                                           "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
            {"id": "MAL-11", "withdrawn": "2026-02-01", "affected": [
                {"package": {"ecosystem": "PyPI", "name": "fastapi"}, "versions": ["0.136.3"]}]},
        ]
        records = [r for doc in osv for r in builder.records_from_osv(doc)]
        blob = builder.encode(records, [{"source": "test"}])
        self.assertEqual(blob[:2], b"\x1f\x8b")
        doc = json.loads(gzip.decompress(blob))
        self.assertEqual(doc["schema"], "ait-malicious-versions/2")
        snap = intel_malicious.parse_snapshot(doc)
        self.assertEqual((snap.record_count, snap.all_versions_count, snap.withdrawn_count), (2, 1, 1))
        self.assertIn(("pypi", "evil-pkg"), snap.records)
        rec = snap.records[("pypi", "evil-pkg")][0]
        self.assertEqual((rec.id, rec.versions, rec.published, rec.aliases, rec.withdrawn),
                         ("MAL-9", ("1.0.1",), "2026-01-02", ("GHSA-x",), None))
        fs = intel_malicious.judge([lib("evil.pkg", "1.0.1"), lib("@scope/spam", "9.9.9", eco="npm"),
                                    lib("fastapi", "0.136.3")], snapshot=snap)
        self.assertEqual({f.advisory_id: f.status for f in fs},
                         {"MAL-9": "new", "MAL-10": "new", "MAL-11": "withdrawn"})

    def test_top_up_applies_a_later_withdrawal(self):
        builder = load_builder()
        active = {"id": "MAL-11", "affected": [
            {"package": {"ecosystem": "PyPI", "name": "fastapi"}, "versions": ["0.136.3"]}]}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "mal.json.gz"
            out.write_bytes(builder.encode(builder.records_from_osv(active), []))
            export = Path(tmp) / "all.zip"
            with zipfile.ZipFile(export, "w") as zf:
                zf.writestr("MAL-11.json", json.dumps(dict(active, withdrawn="2026-02-01T00:00:00Z")))
            with mock.patch("sys.stdout", io.StringIO()):
                builder.main(["--zip", str(export), "--out", str(out)])
            snap = intel_malicious.parse_snapshot(json.loads(gzip.decompress(out.read_bytes())))
        self.assertEqual([(r.id, r.withdrawn) for r in snap.records[("pypi", "fastapi")]],
                         [("MAL-11", "2026-02-01")])

    def test_bundled_snapshot_never_marks_popular_packages_all_versions(self):
        # data-quality gate: a bad build that flags every version of a popular package would turn
        # into a CRITICAL finding for nearly every user
        snap = intel_malicious.load_snapshot()
        popular = {"pypi": ["requests", "numpy", "torch", "transformers", "openai", "litellm", "langchain",
                            "fastapi", "pydantic", "lightning", "mistralai"],
                   "npm": ["react", "lodash", "express", "axios", "chalk", "debug", "openai", "@mastra/core",
                           "@mistralai/mistralai", "typescript", "nx"]}
        for eco, names in popular.items():
            for name in names:
                for rec in snap.records.get((eco, name), []):
                    if rec.withdrawn:
                        continue  # reported as withdrawn, never as malicious
                    self.assertFalse(rec.all_versions, f"{eco}/{name} {rec.id} marks every version malicious")
                    self.assertTrue(rec.versions, f"{eco}/{name} {rec.id} lists no versions")


GHSA = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2024-0001", "PYSEC-2024-1"],
    "summary": "RCE in transformers",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"ecosystem": "PyPI", "name": "transformers"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.48.0"}]}]}],
}
PYSEC = {
    "id": "PYSEC-2024-1",
    "aliases": ["CVE-2024-0001", "GHSA-aaaa-bbbb-cccc"],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "transformers"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.48.0"}]}]}],
}
LOW = {
    "id": "GHSA-low",
    "summary": "minor",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "transformers"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.45.0"}]}]}],
}
MAL = {"id": "MAL-2026-2144", "aliases": ["PYSEC-2026-2"], "summary": "Malicious code in litellm (PyPI)"}


class FakeClient(vulns.OSVClient):
    def __init__(self, ids, docs):
        super().__init__(cache=Cache(enabled=False))
        self._ids, self._docs = ids, docs

    def query_ids(self, queries, result=None):
        return {q: self._ids.get((q[1], q[2]), []) for q in queries}

    def details(self, ids):
        return {i: self._docs[i] for i in ids if i in self._docs}


class VulnTests(unittest.TestCase):
    def test_cvss3(self):
        self.assertEqual(vulns.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(vulns.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(vulns.cvss3_base_score("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"), 2.0)

    def test_alias_dedupe_fix_version_and_mal(self):
        result = ScanResult("t", "online")
        comps = [lib("transformers", "4.44.0"), lib("litellm", "1.82.7")]
        client = FakeClient(
            {("transformers", "4.44.0"): ["GHSA-aaaa-bbbb-cccc", "PYSEC-2024-1", "GHSA-low"],
             ("litellm", "1.82.7"): ["MAL-2026-2144", "PYSEC-2026-2"]},
            {"GHSA-aaaa-bbbb-cccc": GHSA, "PYSEC-2024-1": PYSEC, "GHSA-low": LOW, "MAL-2026-2144": MAL,
             "PYSEC-2026-2": {"id": "PYSEC-2026-2", "aliases": ["MAL-2026-2144"]}},
        )
        fs = vulns.judge(comps, result, client)
        tf = [f for f in fs if f.component.name == "transformers"]
        self.assertEqual(len(tf), 2)  # GHSA+PYSEC grouped, plus the low one
        high = next(f for f in tf if f.advisory_id == "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(high.severity, "high")
        self.assertIn("4.48.0", high.remediation)
        self.assertEqual(next(f for f in tf if f.advisory_id == "GHSA-low").severity, "low")
        mal = [f for f in fs if f.component.name == "litellm"]
        self.assertEqual([(f.rule_id, f.severity) for f in mal], [("ait.pkg.malicious", "critical")])
        # same fingerprint as the snapshot finding, so the scanner merges them
        snap = intel_malicious.judge([comps[1]])
        self.assertEqual(snap[0].fingerprint, mal[0].fingerprint)

    def test_kev_upgrades_to_critical(self):
        result = ScanResult("t", "online")
        client = FakeClient({("transformers", "4.44.0"): ["GHSA-aaaa-bbbb-cccc"]}, {"GHSA-aaaa-bbbb-cccc": GHSA})
        fake_kev = {"count": 1, "cves": {"CVE-2024-0001": {"dateAdded": "2026-01-01"}}}
        with mock.patch.object(vulns, "kev_catalog", return_value=fake_kev):
            fs = vulns.judge([lib("transformers", "4.44.0")], result, client)
        self.assertEqual((fs[0].severity, fs[0].kev, fs[0].rule_id), ("critical", True, "ait.vuln.kev"))
        self.assertEqual(result.examined["kev"].with_data, 1)

    def test_unversioned_noted_not_judged(self):
        result = ScanResult("t", "online")
        fs = vulns.judge([lib("transformers", spec=">=4")], result, FakeClient({}, {}))
        self.assertEqual(fs, [])
        self.assertTrue(any("without an exact version" in n for n in result.notes))

    def test_max_vulns(self):
        result = ScanResult("t", "online")
        client = FakeClient({("transformers", "4.44.0"): ["GHSA-aaaa-bbbb-cccc", "GHSA-low"]},
                            {"GHSA-aaaa-bbbb-cccc": GHSA, "GHSA-low": LOW})
        fs = vulns.judge([lib("transformers", "4.44.0")], result, client, max_vulns=1)
        self.assertEqual([f.advisory_id for f in fs], ["GHSA-aaaa-bbbb-cccc"])


class PolicyTests(unittest.TestCase):
    def _result(self):
        r = ScanResult("t", "offline")
        mal = Finding("ait.pkg.malicious", "mal", "critical", component=lib("litellm", "1.82.7"),
                      advisory_id="MAL-2026-2144")
        unp = Finding("ait.pkg.malicious-unpinned", "unp", "low", component=lib("litellm", path="exp/x.py"))
        vuln = Finding("ait.vuln.advisory", "v", "high", component=lib("openai", "1.50.0"), advisory_id="GHSA-1")
        r.findings = [mal, unp, vuln]
        return r, mal, unp, vuln

    def test_parse_and_lint_errors(self):
        p = pol.parse_policy({"use_context": "weird", "fail_on": ["critical", "bad"],
                              "suppressions": [{"finding": "x", "reason": "r"}], "extra": 1})
        self.assertEqual(len(p.errors), 3)
        self.assertEqual(p.warnings, ["unknown key 'extra' (ignored)"])

    def test_allow_and_ignore_never_silence_malicious(self):
        r, mal, unp, vuln = self._result()
        p = pol.parse_policy({"ignore": [{"rule": "ait.*"}], "allow_packages": ["pkg:pypi/litellm"]})
        failing = pol.apply(r, p)
        self.assertEqual(mal.status, "new")
        self.assertEqual(unp.status, "suppressed")
        self.assertEqual(vuln.status, "suppressed")
        self.assertEqual(failing, [mal])

    def test_suppression_expiry(self):
        r, mal, _, vuln = self._result()
        p = pol.parse_policy({"suppressions": [
            {"finding": "GHSA-1", "until": "2027-06-30", "reason": "patch scheduled", "approved_by": "sec"},
            {"finding": mal.fingerprint, "until": "2026-01-01", "reason": "old"},
        ]})
        failing = pol.apply(r, p, today=dt.date(2026, 11, 14))
        self.assertEqual(vuln.status, "suppressed")
        self.assertEqual(vuln.suppression["approved_by"], "sec")
        self.assertEqual(mal.status, "new")
        self.assertTrue(any("expired" in n for n in r.notes))
        self.assertEqual(failing, [mal])

    def test_baseline_roundtrip(self):
        r, mal, unp, vuln = self._result()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            self.assertEqual(pol.write_baseline(r, path), 3)
            r2, mal2, _, vuln2 = self._result()
            failing = pol.apply(r2, pol.Policy(), pol.load_baseline(path))
        self.assertEqual(vuln2.status, "acknowledged")
        # a baseline never expires, so it never accepts a known-malicious finding
        self.assertEqual(mal2.status, "new")
        self.assertEqual(failing, [mal2])

    def test_broad_suppressions_never_silence_malicious(self):
        r, mal, _, vuln = self._result()
        p = pol.parse_policy({"suppressions": [
            {"rule": "ait.*", "until": "2027-06-30", "reason": "noisy"},
            {"path": "*", "until": "2027-06-30", "reason": "everything"},
            {"finding": "MAL-2026-2144", "until": "2027-06-30", "reason": "advisory-wide"},
        ]})
        failing = pol.apply(r, p, today=dt.date(2026, 11, 14))
        self.assertEqual(vuln.status, "suppressed")
        self.assertEqual(mal.status, "new")
        self.assertEqual(failing, [mal])
        self.assertTrue(any(mal.fingerprint in n for n in r.notes))

    def test_fingerprint_suppression_accepts_malicious(self):
        r, mal, _, _ = self._result()
        p = pol.parse_policy({"suppressions": [
            {"finding": mal.fingerprint, "until": "2027-06-30", "reason": "isolated sandbox"}]})
        failing = pol.apply(r, p, today=dt.date(2026, 11, 14))
        self.assertEqual(mal.status, "suppressed")
        self.assertNotIn(mal, failing)

    def test_every_malicious_verdict_is_protected(self):
        r = ScanResult("t", "offline")
        pickle_hit = Finding("ait.model.pickle.dangerous-global", "os.system in a pickle", "critical",
                             verdict="malicious", location=Location("models/m.pt"))
        r.findings = [pickle_hit]
        failing = pol.apply(r, pol.parse_policy({"ignore": [{"rule": "ait.model.*"}]}))
        self.assertEqual(failing, [pickle_hit])

    def test_deny_packages_and_ranges(self):
        p = pol.parse_policy({"deny_packages": ["pkg:pypi/litellm@1.82.7", "pkg:npm/axios@>=1.14.0"]})
        comps = [lib("litellm", "1.82.7"), lib("litellm", "1.83.0"), lib("axios", "1.14.1", eco="npm")]
        fs = pol.denied_package_findings(comps, p)
        self.assertEqual(sorted(f.component.display for f in fs), ["pkg:npm/axios@1.14.1", "pkg:pypi/litellm@1.82.7"])

    def test_fail_on_threshold(self):
        self.assertEqual(pol.threshold_set("high"), {"critical", "high"})
        self.assertEqual(pol.threshold_set("none"), set())

    def test_snyk_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".snyk"
            path.write_text("version: v1.25.0\nignore:\n  GHSA-1:\n    - '*':\n        reason: accepted\n"
                            "        created: 2026-11-01T00:00:00.000Z\n")
            sups = pol.load_snyk(path)
        self.assertEqual(sups[0].until, dt.date(2026, 12, 1))  # 30-day default
        r, _, _, vuln = self._result()
        p = pol.Policy(suppressions=sups)
        pol.apply(r, p, today=dt.date(2026, 11, 14))
        self.assertEqual(vuln.status, "suppressed")


def _fake_osv(ids: dict, docs: dict):
    """Patch the live OSV calls (only the network layer is replaced)."""
    return (
        mock.patch.object(vulns.OSVClient, "query_ids",
                          lambda self, queries, result=None: {q: ids.get((q[1], q[2]), []) for q in queries}),
        mock.patch.object(vulns.OSVClient, "details", lambda self, wanted: {i: docs[i] for i in wanted if i in docs}),
    )


class ScanHonestyTests(unittest.TestCase):
    """End-to-end: what the scan could not check is reported, never passed as clean."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, **kw):
        kw.setdefault("registry", False)  # no live registry lookups from unit tests
        return run_scan(ScanOptions(target=self.root, cache=Cache(enabled=False), **kw))

    def test_clean_mcp_servers_and_skills_count_as_checked(self):
        shutil.copytree(GOLDEN / "F04b-clean-mcp", self.root / "mcp", dirs_exist_ok=True)
        skill = self.root / "skills" / "notes"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: notes\ndescription: Summarise meeting notes.\n---\n"
                                        "Read the notes the user gives you and write a short summary.\n",
                                        encoding="utf-8")
        result = self.scan(offline=True)
        mcp_ex, skill_ex = result.examined.get("mcp"), result.examined.get("skills")
        self.assertIsNotNone(mcp_ex)
        self.assertGreaterEqual(mcp_ex.checked, 1)
        self.assertEqual(mcp_ex.with_data, 0)
        self.assertIsNotNone(skill_ex)
        self.assertEqual(skill_ex.checked, 1)
        self.assertEqual(skill_ex.with_data, 0)

    def test_scan_runs_registry_checks_and_typosquat_names(self):
        (self.root / "requirements.txt").write_text("reqeusts==2.0.0\nnot-a-real-pkg-xyz==1.0\n")

        def fetch(url, headers):
            raise net.NetError(f"GET {url} -> HTTP 404", status=404)

        with mock.patch("aiterprise_scan.registry._default_fetch", fetch), \
                mock.patch.object(vulns.OSVClient, "query_ids", lambda self, q, result=None: {x: [] for x in q}):
            result = self.scan(registry=True)
        rules = sorted({(f.rule_id, f.component.name) for f in result.findings if f.rule_id.startswith("ait.pkg.")})
        self.assertIn(("ait.pkg.typosquat", "reqeusts"), rules)
        self.assertIn(("ait.pkg.nonexistent", "not-a-real-pkg-xyz"), rules)

    def test_no_registry_still_checks_names(self):
        (self.root / "requirements.txt").write_text("reqeusts==2.0.0\n")
        result = self.scan(offline=True)
        self.assertEqual([f.rule_id for f in result.findings if f.rule_id.startswith("ait.pkg.")],
                         ["ait.pkg.typosquat"])
        self.assertEqual(result.examined["registry"].skipped, "offline")

    def test_unreachable_osv_is_an_incomplete_scan(self):
        (self.root / "requirements.txt").write_text("openai==1.50.0\n")
        with mock.patch.object(vulns.OSVClient, "query_ids", side_effect=net.NetError("connection refused")):
            result = self.scan()
        self.assertEqual(result.exit_code, 2)
        self.assertTrue(any("UNVERIFIED" in n for n in result.notes))

    def test_offline_scan_is_not_an_error(self):
        (self.root / "requirements.txt").write_text("openai==1.50.0\n")
        self.assertEqual(self.scan(offline=True).exit_code, 0)

    def test_live_withdrawal_overrides_the_bundled_snapshot(self):
        (self.root / "requirements.txt").write_text("litellm==1.82.7\n")
        docs = {"MAL-2026-2144": dict(MAL, withdrawn="2026-11-01T00:00:00Z")}
        p1, p2 = _fake_osv({("litellm", "1.82.7"): ["MAL-2026-2144"]}, docs)
        with p1, p2:
            result = self.scan()
        mal = [f for f in result.findings if f.rule_id == "ait.pkg.malicious"]
        self.assertEqual([f.status for f in mal], ["withdrawn"])

    def test_oversized_manifest_is_reported(self):
        (self.root / "requirements.txt").write_text("litellm==1.82.7\n" + "# padding\n" * 20)
        with mock.patch.object(discover, "MAX_MANIFEST_BYTES", 64):
            result = self.scan(offline=True)
        gaps = [f for f in result.findings if f.rule_id == "ait.pkg.not-analysable"]
        self.assertEqual([(f.location.path, f.severity) for f in gaps], [("requirements.txt", "medium")])

    def test_file_cap_is_reported(self):
        for i in range(5):
            (self.root / f"f{i}.txt").write_text("x")
        with mock.patch("aiterprise_scan.walk.DEFAULT_MAX_FILES", 3):
            result = self.scan(offline=True, judge=False)
        self.assertEqual(result.files_walked, 3)
        self.assertTrue(any("3 files" in n and "not examined" in n for n in result.notes))


class TableTests(unittest.TestCase):
    def test_scanned_text_cannot_drive_the_terminal(self):
        r = ScanResult("t", "offline")
        comp = Component("evil\x1b]0;owned\x07server", ctype="mcp-server", locations=[Location(".mcp.json", 1)])
        r.findings = [Finding("ait.mcp.desc.x", "title\x1b[2J‮reversed", "high", component=comp)]
        r.notes = ["config \x1b[31mred\x1b[0m"]
        out = io.StringIO()
        report.render_table(r, out)
        text = out.getvalue()
        for ch in ("\x1b", "\x07", "‮"):
            self.assertNotIn(ch, text)
        self.assertIn("owned", text)
        self.assertIn("reversed", text)


CDXGEN_LIKE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "litellm", "version": "1.82.7", "purl": "pkg:pypi/litellm@1.82.7",
         "hashes": [{"alg": "SHA-256", "content": "AB" * 32}]},
        {"type": "machine-learning-model", "name": "Meta-Llama-3-8B",
         "purl": "pkg:huggingface/meta-llama/Meta-Llama-3-8B@main", "licenses": [{"license": {"name": "llama3"}}]},
        {"type": "library", "name": "app", "components": [
            {"type": "library", "name": "sdk", "group": "@anthropic-ai", "purl": "pkg:npm/%40anthropic-ai/sdk@0.27.0"}]},
    ],
}
SNYK_LIKE = {"bomFormat": "CycloneDX", "specVersion": "1.6",
             "components": [{"type": "library", "name": "litellm", "purl": "pkg:pypi/litellm"}]}


class BomTests(unittest.TestCase):
    def _write(self, tmp, name, doc, utf16=False):
        p = Path(tmp) / name
        text = json.dumps(doc)
        p.write_bytes(("﻿" + text).encode("utf-16-le") if utf16 else text.encode("utf-8"))
        return p

    def test_ingest_cdxgen_style(self):
        with tempfile.TemporaryDirectory() as tmp:
            kind, comps = ingest.ingest_file(self._write(tmp, "bom.json", CDXGEN_LIKE, utf16=True), Path(tmp))
        self.assertEqual(kind, "CycloneDX 1.6")
        by = {c.name: c for c in comps}
        self.assertEqual(by["litellm"].version, "1.82.7")
        self.assertEqual(by["litellm"].hashes["sha256"], "ab" * 32)
        self.assertTrue(by["litellm"].ai)
        self.assertEqual((by["meta-llama/Meta-Llama-3-8B"].ctype, by["meta-llama/Meta-Llama-3-8B"].licence),
                         ("model", "llama3"))
        self.assertIn("@anthropic-ai/sdk", by)

    def test_versionless_bom_marked(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, comps = ingest.ingest_file(self._write(tmp, "snyk.cdx.json", SNYK_LIKE), Path(tmp))
        self.assertIsNone(comps[0].version)
        self.assertEqual(comps[0].properties["unjudgeable"], "no version in BOM")
        self.assertEqual(intel_malicious.judge(comps)[0].rule_id, "ait.pkg.malicious-unpinned")

    def test_not_a_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ingest.BOMError):
                ingest.ingest_file(self._write(tmp, "bom.json", {"hello": 1}), Path(tmp))

    def test_emit_and_reingest(self):
        result = ScanResult("repo", "offline")
        comp = lib("litellm", "1.82.7")
        model = Component("w.pt", ctype="model-file", hashes={"sha256": "cd" * 32}, ai=True,
                          properties={"path": "w.pt", "format": "pickle"}, locations=[Location("w.pt")])
        result.components = [comp, model]
        result.findings = intel_malicious.judge([comp])
        for ver in ("1.6", "1.7"):
            doc = bom.build(result, ver)
            self.assertEqual(doc["specVersion"], ver)
            self.assertEqual(doc["vulnerabilities"][0]["affects"][0]["ref"], "pkg:pypi/litellm@1.82.7")
            self.assertEqual(doc["vulnerabilities"][0]["ratings"][0]["severity"], "critical")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "aibom.cdx.json"
            p.write_text(bom.dumps(result), encoding="utf-8")
            _, comps = ingest.ingest_file(p, Path(tmp))
        back = {c.ctype: c for c in comps}
        self.assertEqual(back["library"].purl, "pkg:pypi/litellm@1.82.7")
        self.assertEqual(back["model-file"].hashes["sha256"], "cd" * 32)

    def test_cli_bom_only_does_not_walk_cwd(self):
        import contextlib
        import io
        import os

        from aiterprise_scan import cli

        with tempfile.TemporaryDirectory() as tmp:
            bom_path = self._write(tmp, "bom.json", CDXGEN_LIKE)
            noise = Path(tmp) / "cwd"
            noise.mkdir()
            (noise / "requirements.txt").write_text("openai==1.50.0\n", encoding="utf-8")
            out = Path(tmp) / "out"
            old_cwd, old_cache = os.getcwd(), os.environ.get("AITERPRISE_CACHE_DIR")
            os.chdir(noise)
            os.environ["AITERPRISE_CACHE_DIR"] = str(Path(tmp) / "cache")
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = cli.main(["scan", "--bom", str(bom_path), "--offline", "--format", "json",
                                     "--out", str(out)])
            finally:
                os.chdir(old_cwd)
                if old_cache is None:
                    os.environ.pop("AITERPRISE_CACHE_DIR", None)
                else:
                    os.environ["AITERPRISE_CACHE_DIR"] = old_cache
            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(code, 1)
        self.assertEqual(rep["summary"]["files_walked"], 0)
        self.assertNotIn("openai", {c["name"] for c in rep["components"]})
        self.assertIn("ait.pkg.malicious", {f["rule_id"] for f in rep["findings"]})

    def test_licence_mapping(self):
        c = Component("m", ctype="model", licence="apache-2.0")
        self.assertEqual(bom._licences(c), [{"license": {"id": "Apache-2.0"}}])
        c.licence = "llama3"
        self.assertEqual(bom._licences(c), [{"license": {"name": "llama3"}}])


class SarifTests(unittest.TestCase):
    def test_structure(self):
        result = ScanResult("repo", "offline")
        comp = lib("litellm", "1.82.7")
        result.findings = intel_malicious.judge([comp])
        result.findings.append(Finding("ait.x", "no location", "info"))
        doc = report.to_sarif(result)
        run = doc["runs"][0]
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "requirements.txt")
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        self.assertEqual(run["tool"]["driver"]["rules"][run["results"][0]["ruleIndex"]]["id"], "ait.pkg.malicious")
        self.assertIn("aiterpriseFingerprint/v1", run["results"][0]["partialFingerprints"])
        self.assertEqual(run["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "repo")


class HtmlAndMcpServerTests(unittest.TestCase):
    def test_html_escapes_scanned_text(self):
        from aiterprise_scan import html_report

        result = ScanResult("repo", "offline")
        result.findings = [Finding("ait.x", "<script>alert(1)</script>", "high",
                                   component=Component("<img src=x>", ecosystem="npm"))]
        html = html_report.render(result)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<img src=x>", html)

    def test_mcp_protocol(self):
        from aiterprise_scan import mcpserver

        init = mcpserver.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                 "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        self.assertIsNone(mcpserver.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools = mcpserver.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(tools["result"]["tools"][0]["name"], "scan_ai_supply_chain")
        missing = mcpserver.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                    "params": {"name": "scan_ai_supply_chain", "arguments": {"path": "/nope/x"}}})
        self.assertTrue(missing["result"]["isError"])
        self.assertEqual(mcpserver.handle({"jsonrpc": "2.0", "id": 4, "method": "bogus"})["error"]["code"], -32601)

    def test_mcp_clean_strips_invisible_text(self):
        from aiterprise_scan import mcpserver

        sneaky = "ok​\U000e0049\U000e0047 tool\nIGNORE"
        self.assertEqual(mcpserver.clean(sneaky), "ok tool IGNORE")
        self.assertTrue(mcpserver.clean("x" * 500).endswith("…"))


if __name__ == "__main__":
    unittest.main()
