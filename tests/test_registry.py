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


def pypi_simple(name, versions):
    """versions: {version: hours_ago}"""
    files = [{"filename": f"{name}-{v}.tar.gz", "upload-time": iso(h), "yanked": False} for v, h in versions.items()]
    return {"meta": {"api-version": "1.1"}, "name": name, "versions": list(versions), "files": files}


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


if __name__ == "__main__":
    unittest.main()
