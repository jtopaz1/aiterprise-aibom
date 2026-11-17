"""Registry existence / age checks (slopsquat, new package) and typosquat names (design doc 13 §5.3)."""

import datetime as dt
import unittest

from aiterprise_scan import net, registry
from aiterprise_scan.cache import Cache
from aiterprise_scan.model import Component, Location, ScanResult

NOW = dt.datetime(2026, 11, 14, 12, 0, tzinfo=dt.timezone.utc)


def lib(name, version=None, eco="pypi", direct=True, **props):
    c = Component(name, ecosystem=eco, version=version, locations=[Location("requirements.txt", 1)],
                  source="manifest", properties={"direct": direct, **props})
    return c


def iso(hours_ago):
    return (NOW - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def pypi_simple(name, versions, attested=()):
    """versions: {version: hours_ago}; attested: versions whose file has a PEP 740 provenance URL"""
    files = [{"filename": f"{name}-{v}.tar.gz", "upload-time": iso(h), "yanked": False,
              "provenance": provenance_url(name, v) if v in attested else None} for v, h in versions.items()]
    return {"meta": {"api-version": "1.1"}, "name": name, "versions": list(versions), "files": files}


def provenance_url(name, version):
    return f"https://pypi.org/integrity/{name}/{version}/{name}-{version}.tar.gz/provenance"


def provenance(repository, workflow="release.yml"):
    return {"version": 1, "attestation_bundles": [
        {"publisher": {"kind": "GitHub", "repository": repository, "workflow": workflow, "environment": "pypi"},
         "attestations": []}]}


TRUSTED = {"name": "GitHub Actions", "email": "npm-oidc-no-reply@github.com",
           "trustedPublisher": {"id": "github", "oidcConfigId": "x"}}


class FakeFetch:
    def __init__(self, docs):
        self.docs = docs
        self.urls = []

    def __call__(self, url, headers):
        self.urls.append(url)
        if "npmjs" in url and headers.get("Accept") == "application/json":
            url += "#full"  # the full npm document (with publish times) vs the abbreviated one
        if url not in self.docs:
            raise net.NetError(f"GET {url} -> HTTP 404", status=404)
        doc = self.docs[url]
        if isinstance(doc, Exception):
            raise doc
        return doc


def client(docs, offline=False):
    fetch = FakeFetch(docs)
    return registry.RegistryClient(cache=Cache(enabled=False), offline=offline, fetch=fetch, now=lambda: NOW), fetch


PYPI = "https://pypi.org/simple/{}/"
NPM = "https://registry.npmjs.org/{}"


class ExistenceTests(unittest.TestCase):
    def test_nonexistent_pypi_package_is_a_slopsquat_risk(self):
        c, _ = client({})
        result = ScanResult("t", "online")
        fs = registry.judge([lib("langchain-openai-tools-pro", "0.1.0")], result, c)
        self.assertEqual([(f.rule_id, f.severity, f.verdict) for f in fs],
                         [("ait.pkg.nonexistent", "high", "suspicious")])
        self.assertIn("PyPI", fs[0].title)
        self.assertEqual(fs[0].evidence[0].source, "pypi")
        ex = result.examined["registry"]
        self.assertEqual((ex.checked, ex.with_data), (1, 1))

    def test_old_existing_package_is_quiet(self):
        c, _ = client({PYPI.format("requests"): pypi_simple("requests", {"2.31.0": 20000, "2.32.3": 9000})})
        result = ScanResult("t", "online")
        self.assertEqual(registry.judge([lib("requests", "2.32.3")], result, c), [])
        self.assertEqual(result.examined["registry"].checked, 1)

    def test_brand_new_package_is_flagged(self):
        c, _ = client({PYPI.format("llm-guard-fast"): pypi_simple("llm-guard-fast", {"0.0.1": 10})})
        fs = registry.judge([lib("llm-guard-fast", "0.0.1")], ScanResult("t", "online"), c)
        self.assertEqual([(f.rule_id, f.severity) for f in fs], [("ait.pkg.new-package", "medium")])
        self.assertIn("10 hours", fs[0].title)

    def test_pinned_version_missing_from_registry(self):
        c, _ = client({PYPI.format("litellm"): pypi_simple("litellm", {"1.82.6": 6000, "1.82.9": 5000})})
        fs = registry.judge([lib("litellm", "1.82.7")], ScanResult("t", "online"), c)
        self.assertEqual([(f.rule_id, f.severity) for f in fs], [("ait.pkg.version-missing", "medium")])

    def test_npm_nonexistent_and_security_holder(self):
        holder = {"name": "evil-ai-sdk", "versions": {"0.0.1-security": {}}, "dist-tags": {"latest": "0.0.1-security"}}
        c, _ = client({NPM.format("evil-ai-sdk"): holder})
        fs = registry.judge([lib("evil-ai-sdk", "1.2.0", "npm"), lib("totally-made-up-llm-pkg", "1.0.0", "npm")],
                            ScanResult("t", "online"), c)
        got = sorted((f.rule_id, f.severity, f.verdict, f.component.name) for f in fs)
        self.assertEqual(got, [("ait.pkg.nonexistent", "high", "suspicious", "totally-made-up-llm-pkg"),
                               ("ait.pkg.security-holder", "critical", "malicious", "evil-ai-sdk")])

    def test_npm_new_package_needs_full_document_for_times(self):
        abbreviated = {"name": "agent-tools-x", "versions": {"1.0.0": {}}, "dist-tags": {"latest": "1.0.0"}}
        full = {"name": "agent-tools-x", "time": {"created": iso(30), "1.0.0": iso(30)}}
        docs = {NPM.format("agent-tools-x"): abbreviated, NPM.format("agent-tools-x") + "#full": full}
        c, fetch = client(docs)
        fs = registry.judge([lib("agent-tools-x", "1.0.0", "npm")], ScanResult("t", "online"), c)
        self.assertEqual([f.rule_id for f in fs], ["ait.pkg.new-package"])

    def test_offline_makes_no_requests(self):
        c, fetch = client({}, offline=True)
        result = ScanResult("t", "offline")
        registry.judge([lib("whatever-pkg", "1.0")], result, c)
        self.assertEqual(fetch.urls, [])
        self.assertEqual(result.examined["registry"].skipped, "offline")

    def test_transitive_and_url_sourced_packages_are_not_queried(self):
        c, fetch = client({})
        result = ScanResult("t", "online")
        fs = registry.judge([lib("deep-dep", "1.0", direct=False),
                             lib("internal", "1.0", url="git+https://git.example/internal@abc"),
                             lib("private", "1.0", index="https://pypi.internal.example/simple")], result, c)
        self.assertEqual((fs, fetch.urls), ([], []))
        self.assertTrue(any("1 transitive" in n for n in result.notes), result.notes)

    def test_registry_outage_is_unverified_not_clean(self):
        c, _ = client({PYPI.format("requests"): net.NetError("GET -> HTTP 503", status=503)})
        result = ScanResult("t", "online")
        self.assertEqual(registry.judge([lib("requests", "2.32.3")], result, c), [])
        self.assertEqual(result.examined["registry"].errors, 1)
        self.assertTrue(any("UNVERIFIED" in n for n in result.notes))


class TyposquatTests(unittest.TestCase):
    def judge(self, *comps):
        c, _ = client({}, offline=True)
        return [f for f in registry.judge(list(comps), ScanResult("t", "offline"), c)
                if f.rule_id == "ait.pkg.typosquat"]

    def test_one_edit_from_a_popular_name(self):
        fs = self.judge(lib("reqeusts", "2.0"), lib("langchian", "0.1"))
        self.assertEqual(sorted(f.evidence[0].detail["looks_like"] for f in fs), ["langchain", "requests"])
        self.assertEqual({f.severity for f in fs}, {"medium"})

    def test_separator_games(self):
        fs = self.judge(lib("open-ai", "1.0", "npm"))
        self.assertEqual([f.evidence[0].detail["looks_like"] for f in fs], ["openai"])

    def test_scoped_npm_name(self):
        fs = self.judge(lib("@langchian/core", "0.3.0", "npm"))
        self.assertEqual([f.evidence[0].detail["looks_like"] for f in fs], ["@langchain/core"])

    def test_real_packages_and_short_names_are_quiet(self):
        self.assertEqual(self.judge(lib("requests", "2.0"), lib("openai", "1.0"), lib("torch", "2.0"),
                                    lib("pyaml", "1.0"), lib("six", "1.0"), lib("numpy", "1.0"),
                                    lib("transformers", "4.0")), [])

    def test_the_kind_of_slip_is_named(self):
        kinds = {f.component.name: f.evidence[0].detail["typo"]
                 for f in self.judge(lib("reqeusts"), lib("rquests"), lib("requestss"), lib("requeats"),
                                     lib("requbsts"), lib("open-ai", eco="npm"))}
        self.assertEqual(kinds, {"reqeusts": "transposition", "rquests": "omission", "requestss": "repetition",
                                 "requeats": "adjacent-key", "requbsts": "substitution", "open-ai": "separator"})
        fs = self.judge(lib("requeats"))
        self.assertIn("one adjacent-key slip from", fs[0].title)
        # a finger slip is likelier than an arbitrary letter change
        self.assertGreater(fs[0].confidence, self.judge(lib("requbsts"))[0].confidence)

    def test_lookalike_letters(self):
        # rn reads as m, vv as w, cl as d, 0 as o, 1 as l: no edit distance limit catches nurnpy
        fs = self.judge(lib("nurnpy"), lib("panclas"))
        self.assertEqual(sorted((f.evidence[0].detail["looks_like"], f.evidence[0].detail["typo"]) for f in fs),
                         [("numpy", "homoglyph"), ("pandas", "homoglyph")])

    def test_known_legitimate_near_names_are_quiet(self):
        # measured: real packages installed on a developer machine that are one edit from a popular name
        self.assertEqual(self.judge(lib("psycopg"), lib("psycopg-binary"), lib("pycryptodomex"),
                                    lib("safer-buffer", eco="npm")), [])


class ShortNameTests(unittest.TestCase):
    """A 4-letter popular name is one keystroke from many real packages (xlsx/clsx, blob/glob), and
    from many squats: only the registry can tell an established package from a new one."""

    def test_offline_a_short_lookalike_is_not_judged_but_said(self):
        c, _ = client({}, offline=True)
        result = ScanResult("t", "offline")
        self.assertEqual(registry.judge([lib("jesr", "1.0.0", "npm")], result, c), [])
        self.assertTrue(any("jesr" in n and "jest" in n for n in result.notes), result.notes)

    def test_a_young_short_lookalike_is_flagged(self):
        abbreviated = {"name": "jesr", "versions": {"1.0.0": {}}, "dist-tags": {"latest": "1.0.0"}}
        full = {"name": "jesr", "time": {"created": iso(24 * 20), "1.0.0": iso(24 * 20)}}
        c, _ = client({NPM.format("jesr"): abbreviated, NPM.format("jesr") + "#full": full})
        fs = registry.judge([lib("jesr", "1.0.0", "npm")], ScanResult("t", "online"), c)
        self.assertEqual([(f.rule_id, f.evidence[0].detail["looks_like"], f.evidence[0].detail["typo"]) for f in fs],
                         [("ait.pkg.typosquat", "jest", "adjacent-key")])
        self.assertIn("20 days", fs[0].title)

    def test_an_established_short_lookalike_is_quiet(self):
        c, _ = client({PYPI.format("lxmk"): pypi_simple("lxmk", {"0.1": 24 * 800})})
        self.assertEqual(registry.judge([lib("lxmk", "0.1")], ScanResult("t", "online"), c), [])

    def test_a_short_name_transposition_counts_but_other_edits_do_not(self):
        young = {"0.1": 24 * 3 + 100}
        c, _ = client({PYPI.format(n): pypi_simple(n, young) for n in ("rfuf", "lxmz")})
        fs = registry.judge([lib("rfuf", "0.1"), lib("lxmz", "0.1")], ScanResult("t", "online"), c)
        self.assertEqual([(f.component.name, f.evidence[0].detail["typo"]) for f in fs if f.rule_id == "ait.pkg.typosquat"],
                         [("rfuf", "transposition")])


class ReleaseSignalTests(unittest.TestCase):
    """Release timing from the registry: a long-quiet package that suddenly releases, and a version
    number that jumps far ahead — both only for releases of the last 30 days."""

    def findings(self, name, versions, pinned):
        c, _ = client({PYPI.format(name): pypi_simple(name, versions)})
        return [f for f in registry.judge([lib(name, pinned)], ScanResult("t", "online"), c)
                if f.rule_id in ("ait.pkg.dormant-release", "ait.pkg.version-jump")]

    def test_a_dormant_package_that_suddenly_releases(self):
        fs = self.findings("old-helper", {"1.0": 24 * 365 * 4, "1.1": 24 * 5}, "1.1")
        self.assertEqual([(f.rule_id, f.severity, f.verdict) for f in fs],
                         [("ait.pkg.dormant-release", "medium", "suspicious")])
        self.assertIn("5 days ago", fs[0].title)
        self.assertEqual(fs[0].evidence[0].detail["quiet_days"], 365 * 4 - 5)

    def test_quiet_periods_and_old_releases_that_are_not_signals(self):
        self.assertEqual(self.findings("helper", {"1.0": 24 * 600, "1.1": 24 * 5}, "1.1"), [])        # < 2 years
        self.assertEqual(self.findings("helper", {"1.0": 24 * 2000, "1.1": 24 * 90}, "1.1"), [])     # > 30 days ago
        self.assertEqual(self.findings("helper", {"1.0": 24 * 2000, "1.1": 24 * 5}, "1.0"), [])      # pinned old one

    def test_an_unpinned_dependency_is_judged_by_the_newest_release(self):
        fs = self.findings("old-helper", {"1.0": 24 * 365 * 4, "1.1": 24 * 5}, None)
        self.assertEqual([f.rule_id for f in fs], ["ait.pkg.dormant-release"])
        self.assertEqual(fs[0].evidence[0].detail["version"], "1.1")

    def test_a_version_that_jumps_far_ahead(self):
        fs = self.findings("corp-utils", {"1.2.0": 24 * 400, "1.3.0": 24 * 200, "99.0.0": 24 * 2}, "99.0.0")
        self.assertEqual([(f.rule_id, f.severity) for f in fs], [("ait.pkg.version-jump", "medium")])
        self.assertEqual(fs[0].evidence[0].detail["previous_major"], 1)
        self.assertIn("99.0.0", fs[0].title)

    def test_version_changes_that_are_not_jumps(self):
        self.assertEqual(self.findings("lib", {"3.4.8": 24 * 100, "2026.1": 24 * 2}, "2026.1"), [])    # to CalVer
        self.assertEqual(self.findings("lib", {"3.4.8": 24 * 800, "35.0.0": 24 * 700}, "35.0.0"), [])  # long ago
        self.assertEqual(self.findings("lib", {"1.0.0": 24 * 100, "9.0.0": 24 * 2}, "9.0.0"), [])      # +8
        self.assertEqual(self.findings("lib", {"0.1": 24 * 2}, "0.1"), [])                            # first release
        # measured against the highest earlier major, not the first release
        self.assertEqual(self.findings("lib", {"1.0.0": 24 * 900, "12.0.0": 24 * 300, "15.0.0": 24 * 2}, "15.0.0"), [])


PUBLISHER_RULES = ("ait.pkg.provenance-dropped", "ait.pkg.publisher-change")


class PypiPublisherTests(unittest.TestCase):
    """Who published the release in use, from PEP 740 attestations (design doc 13 C17)."""

    def findings(self, versions, pinned, attested, extra=None):
        c, fetch = client({PYPI.format("tool"): pypi_simple("tool", versions, attested), **(extra or {})})
        fs = [f for f in registry.judge([lib("tool", pinned)], ScanResult("t", "online"), c)
              if f.rule_id in PUBLISHER_RULES]
        return fs, fetch

    def test_a_release_without_the_attestation_earlier_releases_had(self):
        # the second ultralytics wave: uploaded with a stolen token, not by the trusted publisher
        fs, _ = self.findings({"1.0": 24 * 100, "1.1": 24 * 50, "1.2": 24 * 3}, "1.2", attested={"1.0", "1.1"})
        self.assertEqual([(f.rule_id, f.severity, f.verdict) for f in fs],
                         [("ait.pkg.provenance-dropped", "medium", "suspicious")])
        self.assertIn("1.1", fs[0].title)
        self.assertEqual(fs[0].evidence[0].detail["previous"], "1.1")

    def test_attestations_that_are_not_signals(self):
        self.assertEqual(self.findings({"1.1": 24 * 50, "1.2": 24 * 3}, "1.2", attested={"1.1", "1.2"})[0], [])
        self.assertEqual(self.findings({"1.1": 24 * 50, "1.2": 24 * 3}, "1.2", attested=())[0], [])        # never
        self.assertEqual(self.findings({"1.1": 24 * 50, "1.2": 24 * 3}, "1.2", attested={"1.2"})[0], [])   # began
        self.assertEqual(self.findings({"1.1": 24 * 90, "1.2": 24 * 40}, "1.2", attested={"1.1"})[0], [])  # old

    def test_a_backport_is_compared_with_its_own_line(self):
        # 2.x moved to trusted publishing; the 1.x line is still uploaded by hand, and 1.9.1 came out last
        versions = {"1.9": 24 * 400, "2.0": 24 * 100, "2.1": 24 * 50, "1.9.1": 24 * 3}
        self.assertEqual(self.findings(versions, "1.9.1", attested={"2.0", "2.1"})[0], [])

    def test_an_attestation_from_another_repository(self):
        extra = {provenance_url("tool", "1.1"): provenance("acme/tool"),
                 provenance_url("tool", "1.2"): provenance("someone/tool-fork")}
        fs, _ = self.findings({"1.1": 24 * 50, "1.2": 24 * 3}, "1.2", attested={"1.1", "1.2"}, extra=extra)
        self.assertEqual([f.rule_id for f in fs], ["ait.pkg.publisher-change"])
        self.assertEqual((fs[0].evidence[0].detail["publisher"], fs[0].evidence[0].detail["previous_publisher"]),
                         ("someone/tool-fork", "acme/tool"))

    def test_another_workflow_in_the_same_repository_is_quiet(self):
        extra = {provenance_url("tool", "1.1"): provenance("acme/tool", "publish.yml"),
                 provenance_url("tool", "1.2"): provenance("acme/tool", "release.yml")}
        self.assertEqual(self.findings({"1.1": 24 * 50, "1.2": 24 * 3}, "1.2", {"1.1", "1.2"}, extra)[0], [])

    def test_provenance_is_fetched_only_for_a_recent_release(self):
        _, fetch = self.findings({"1.1": 24 * 90, "1.2": 24 * 40}, "1.2", attested={"1.1", "1.2"})
        self.assertFalse([u for u in fetch.urls if "/integrity/" in u])


class NpmPublisherTests(unittest.TestCase):
    """npm records who published each version (`_npmUser`) and the maintainers at the time."""

    VERSIONS = ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "2.0.0", "2.0.1"]  # more than 5: no full document

    def findings(self, current, previous, modified_hours=48, pinned="2.0.1"):
        abbreviated = {"name": "lib-x", "dist-tags": {"latest": "2.0.1"}, "modified": iso(modified_hours),
                       "versions": {v: {} for v in self.VERSIONS}}
        docs = {NPM.format("lib-x"): abbreviated,
                NPM.format("lib-x") + "/2.0.1#full": {"name": "lib-x", "version": "2.0.1", **current},
                NPM.format("lib-x") + "/2.0.0#full": {"name": "lib-x", "version": "2.0.0", **previous}}
        c, fetch = client(docs)
        fs = [f for f in registry.judge([lib("lib-x", pinned, "npm")], ScanResult("t", "online"), c)
              if f.rule_id in PUBLISHER_RULES]
        return sorted((f.rule_id, f.evidence[0].detail.get("publisher")) for f in fs), fetch

    def test_a_publisher_who_was_not_a_maintainer(self):
        # event-stream: a newcomer was handed the package and published the malicious release
        got, _ = self.findings({"_npmUser": {"name": "newcomer"}, "maintainers": [{"name": "newcomer"}]},
                               {"_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}]})
        self.assertEqual(got, [("ait.pkg.publisher-change", "newcomer")])

    def test_a_human_upload_after_trusted_publishing(self):
        got, _ = self.findings({"_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}]},
                               {"_npmUser": TRUSTED, "maintainers": [{"name": "alice"}]})
        self.assertEqual(got, [("ait.pkg.provenance-dropped", "alice")])

    def test_a_release_without_the_provenance_the_previous_one_had(self):
        # `npm publish --provenance` from CI signs a release even without trusted publishing
        signed = {"attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/lib-x@2.0.0",
                                   "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}}
        got, _ = self.findings({"_npmUser": {"name": "alice"}, "dist": {"shasum": "x"}},
                               {"_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}], "dist": signed})
        self.assertEqual(got, [("ait.pkg.provenance-dropped", "alice")])

    def test_publishers_that_are_not_signals(self):
        alice_and_bob = [{"name": "alice"}, {"name": "bob"}]
        quiet = [
            ({"_npmUser": {"name": "bob"}}, {"_npmUser": {"name": "alice"}, "maintainers": alice_and_bob}),
            ({"_npmUser": {"name": "alice"}}, {"_npmUser": {"name": "alice"}, "maintainers": []}),
            ({"_npmUser": TRUSTED}, {"_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}]}),  # moved up
            ({"_npmUser": TRUSTED}, {"_npmUser": TRUSTED, "maintainers": [{"name": "alice"}]}),
        ]
        for current, previous in quiet:
            with self.subTest(current=current, previous=previous):
                self.assertEqual(self.findings(current, previous)[0], [])

    def test_only_a_recent_latest_release_is_looked_up(self):
        stranger = ({"_npmUser": {"name": "x"}}, {"_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}]})
        got, fetch = self.findings(*stranger, modified_hours=24 * 60)
        self.assertEqual((got, [u for u in fetch.urls if u.endswith(("/2.0.1", "/2.0.0"))]), ([], []))
        got, fetch = self.findings(*stranger, pinned="1.3.0")  # an older pin: no publish time to judge it by
        self.assertEqual((got, [u for u in fetch.urls if u.endswith(("/2.0.1", "/2.0.0", "/1.3.0"))]), ([], []))


if __name__ == "__main__":
    unittest.main()
