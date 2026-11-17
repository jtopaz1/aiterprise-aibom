"""Package licences (design doc 13 §5.3, "package licences from manifest + deps.dev"): what the
lockfile records offline, what deps.dev says online, and what each report shows."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import bom, net, pkglicences, registry, vulns
from aiterprise_scan.cache import Cache
from aiterprise_scan.discover import discover_packages
from aiterprise_scan.model import Component, Location, ScanResult
from aiterprise_scan.report import dumps_json
from aiterprise_scan.scanner import ScanOptions, run_scan

DEPS_DEV = "https://api.deps.dev/v3/systems/"

LOCK = {
    "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "app", "version": "1.0.0",
             "dependencies": {"axios": "^1.7.0", "left-pad": "1.3.0", "legacy": "1.0.0", "bare": "2.0.0"}},
        "node_modules/axios": {"version": "1.7.9", "license": "MIT"},
        "node_modules/left-pad": {"version": "1.3.0", "license": "WTFPL OR MIT"},
        "node_modules/legacy": {"version": "1.0.0", "license": {"type": "ISC", "url": "https://example.org/isc"}},
        "node_modules/bare": {"version": "2.0.0"},
    },
}

ANSWERS = {  # what deps.dev's version endpoint says, by URL
    DEPS_DEV + "PYPI/packages/transformers/versions/4.44.0": {"licenses": ["Apache-2.0"]},
    DEPS_DEV + "PYPI/packages/ruamel-yaml/versions/0.18.6": {"licenses": ["MIT"]},
    DEPS_DEV + "NPM/packages/%40types%2Fnode/versions/20.11.0": {"licenses": ["MIT"]},
    DEPS_DEV + "PYPI/packages/twolic/versions/1.0": {"licenses": ["MIT", "Apache-2.0 OR BSD-3-Clause"]},
    DEPS_DEV + "PYPI/packages/flask/versions/3.0.0": {"licenses": ["non-standard"]},
}


def _files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


def _lib(name, eco, version=None, **kw):
    comp = Component(name=name, ctype="library", version=version, ecosystem=eco,
                     locations=[Location("requirements.txt" if eco == "pypi" else "package.json", 1)],
                     source="requirements" if eco == "pypi" else "package.json")
    for key, value in kw.items():
        if key == "licence":
            comp.licence = value
        elif key == "spec":
            comp.version_spec = value
        else:
            comp.properties[key] = value
    return comp


class Fetch:
    """deps.dev, as a dict of answers; anything else is a 404. Records each URL asked."""

    def __init__(self, answers, fail=()):
        self.answers, self.fail, self.urls = answers, set(fail), []

    def __call__(self, url, headers):
        self.urls.append(url)
        if url in self.fail:
            raise net.NetError(f"GET {url} -> HTTP 503", status=503)
        if url in self.answers:
            return self.answers[url]
        raise net.NetError(f"GET {url} -> HTTP 404", status=404)


class LockfileLicenceTests(unittest.TestCase):
    """Offline: npm lockfiles (v2/v3) record each package's licence."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_lockfile_licence_is_the_component_licence(self):
        (self.root / "package-lock.json").write_text(json.dumps(LOCK, indent=2), encoding="utf-8")
        comps = {c.name: c for c in discover_packages(self.root, _files(self.root))}
        self.assertEqual(comps["axios"].licence, "MIT")
        self.assertEqual(comps["left-pad"].licence, "WTFPL OR MIT")
        self.assertEqual(comps["legacy"].licence, "ISC")  # the old {"type": ...} form
        self.assertIsNone(comps["bare"].licence)

    def test_a_licence_from_any_lockfile_survives_the_merge(self):
        # the same package and version in two lockfiles: the first one read records no licence
        bare = {**LOCK, "packages": {"": LOCK["packages"][""],
                                     "node_modules/axios": {"version": "1.7.9"}}}
        (self.root / "a").mkdir()
        (self.root / "b").mkdir()
        (self.root / "a" / "package-lock.json").write_text(json.dumps(bare), encoding="utf-8")
        (self.root / "b" / "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
        axios = [c for c in discover_packages(self.root, _files(self.root)) if c.name == "axios"]
        self.assertEqual(len(axios), 1)
        self.assertEqual(axios[0].licence, "MIT")
        self.assertEqual(len(axios[0].locations), 2)

    def test_the_bom_and_the_json_report_carry_the_lockfile_licence(self):
        (self.root / "package-lock.json").write_text(json.dumps(LOCK, indent=2), encoding="utf-8")
        result = run_scan(ScanOptions(target=self.root, offline=True, cache=Cache(enabled=False)))
        cdx = {c["name"]: c for c in bom.build(result)["components"]}
        self.assertEqual(cdx["axios"]["licenses"], [{"license": {"id": "MIT", "acknowledgement": "declared"}}])
        self.assertEqual(cdx["left-pad"]["licenses"], [{"expression": "WTFPL OR MIT", "acknowledgement": "declared"}])
        self.assertNotIn("licenses", cdx["bare"])
        report = {c["name"]: c for c in json.loads(dumps_json(result))["components"]}
        self.assertEqual(report["axios"]["licence"], "MIT")
        # an offline scan asked nobody, and says so
        self.assertEqual(result.examined["deps.dev"].skipped, "offline")
        self.assertEqual(result.examined["deps.dev"].checked, 0)

    def test_the_bom_command_carries_the_lockfile_licence(self):
        import io

        from aiterprise_scan.cli import main

        (self.root / "package-lock.json").write_text(json.dumps(LOCK, indent=2), encoding="utf-8")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(main(["bom", str(self.root), "--no-cache"]), 0)
        cdx = {c["name"]: c for c in json.loads(out.getvalue())["components"]}
        self.assertEqual(cdx["legacy"]["licenses"], [{"license": {"id": "ISC", "acknowledgement": "declared"}}])


class DepsDevTests(unittest.TestCase):
    """Online: each pinned PyPI / npm package still without a licence is looked up on deps.dev."""

    def judge(self, comps, fetch, offline=False, cache=None):
        client = registry.RegistryClient(cache=cache or Cache(enabled=False), offline=offline, fetch=fetch)
        result = ScanResult(target="t", mode="offline" if offline else "online")
        pkglicences.judge(comps, result, client)
        return result

    def test_pinned_packages_without_a_licence_get_the_one_deps_dev_records(self):
        transformers = [_lib("transformers", "pypi", "4.44.0"), _lib("transformers", "pypi", "4.44.0")]
        comps = transformers + [
            _lib("ruamel.yaml", "pypi", "0.18.6"),  # asked under its normalised name
            _lib("@types/node", "npm", "20.11.0"),  # scope and slash escaped
            _lib("twolic", "pypi", "1.0"),
            _lib("flask", "pypi", "3.0.0"),
            _lib("notfound", "pypi", "1.0"),
            _lib("axios", "npm", "1.7.9", licence="MIT"),  # the lockfile said
            _lib("requests", "pypi", spec=">=2"),  # no exact version
            _lib("private", "pypi", "1.0", index="https://pypi.internal/simple"),  # not a public package
            _lib("fromgit", "npm", "1.0.0", url="git+https://example.org/x.git"),
            _lib("torch", "conda", "2.4.0"),  # deps.dev has no conda
            Component(name="numpy", ctype="library", ecosystem="pypi", source="import"),
        ]
        fetch = Fetch(ANSWERS)
        result = self.judge(comps, fetch)
        self.assertEqual(sorted(fetch.urls), sorted([
            DEPS_DEV + "PYPI/packages/transformers/versions/4.44.0",
            DEPS_DEV + "PYPI/packages/ruamel-yaml/versions/0.18.6",
            DEPS_DEV + "NPM/packages/%40types%2Fnode/versions/20.11.0",
            DEPS_DEV + "PYPI/packages/twolic/versions/1.0",
            DEPS_DEV + "PYPI/packages/flask/versions/3.0.0",
            DEPS_DEV + "PYPI/packages/notfound/versions/1.0",
        ]))  # one request per name and version
        lic = {c.name: c.licence for c in comps}
        self.assertEqual([c.licence for c in transformers], ["Apache-2.0", "Apache-2.0"])
        self.assertEqual(lic["ruamel.yaml"], "MIT")
        self.assertEqual(lic["@types/node"], "MIT")
        self.assertEqual(lic["twolic"], "MIT AND (Apache-2.0 OR BSD-3-Clause)")  # every one listed applies
        self.assertIsNone(lic["flask"])  # deps.dev could not map it to SPDX: left empty, never "non-standard"
        self.assertIsNone(lic["notfound"])
        self.assertEqual(lic["axios"], "MIT")
        ex = result.examined["deps.dev"]
        self.assertEqual((ex.checked, ex.with_data, ex.errors), (6, 4, 0))
        self.assertEqual([n for n in result.notes if n.startswith("deps.dev")],
                         ["deps.dev: 1 package version(s) declare a licence deps.dev does not map to SPDX "
                          "(\"non-standard\"), so the BOM leaves it empty: flask 3.0.0"])

    def test_a_failed_lookup_is_counted_and_named(self):
        url = DEPS_DEV + "PYPI/packages/transformers/versions/4.44.0"
        comps = [_lib("transformers", "pypi", "4.44.0"), _lib("ruamel.yaml", "pypi", "0.18.6")]
        result = self.judge(comps, Fetch(ANSWERS, fail={url}))
        self.assertIsNone(comps[0].licence)
        self.assertEqual(comps[1].licence, "MIT")
        ex = result.examined["deps.dev"]
        self.assertEqual((ex.checked, ex.with_data, ex.errors), (1, 1, 1))
        notes = [n for n in result.notes if n.startswith("deps.dev")]
        self.assertEqual(len(notes), 1)
        self.assertIn("1 licence lookup(s) failed", notes[0])
        self.assertIn("transformers 4.44.0", notes[0])

    def test_offline_asks_nobody(self):
        comps = [_lib("transformers", "pypi", "4.44.0")]
        fetch = Fetch(ANSWERS)
        result = self.judge(comps, fetch, offline=True)
        self.assertEqual(fetch.urls, [])
        self.assertIsNone(comps[0].licence)
        self.assertEqual(result.examined["deps.dev"].skipped, "offline")

    def test_answers_are_cached_404s_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Cache(root=Path(tmp))
            self.judge([_lib("transformers", "pypi", "4.44.0"), _lib("notfound", "pypi", "1.0")],
                       Fetch(ANSWERS), cache=cache)
            again = [_lib("transformers", "pypi", "4.44.0"), _lib("notfound", "pypi", "1.0")]
            fetch = Fetch({}, fail=set(ANSWERS) | {DEPS_DEV + "PYPI/packages/notfound/versions/1.0"})
            result = self.judge(again, fetch, cache=cache)
        self.assertEqual(fetch.urls, [])
        self.assertEqual(again[0].licence, "Apache-2.0")
        ex = result.examined["deps.dev"]
        self.assertEqual((ex.checked, ex.with_data, ex.errors), (2, 1, 0))


class ScanWiringTests(unittest.TestCase):
    """The scan asks deps.dev online, with the registry switch, before the BOM is written."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "requirements.txt").write_text("transformers==4.44.0\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, fetch, **kw):
        with mock.patch("aiterprise_scan.registry._default_fetch", fetch), \
                mock.patch.object(vulns.OSVClient, "query_ids", lambda self, q, result=None: {x: [] for x in q}):
            return run_scan(ScanOptions(target=self.root, cache=Cache(enabled=False), **kw))

    def test_an_online_scan_records_the_deps_dev_licence(self):
        fetch = Fetch(ANSWERS)
        result = self.scan(fetch)
        self.assertIn(DEPS_DEV + "PYPI/packages/transformers/versions/4.44.0", fetch.urls)
        comp = next(c for c in result.components if c.name == "transformers")
        self.assertEqual(comp.licence, "Apache-2.0")
        self.assertEqual(result.examined["deps.dev"].checked, 1)
        self.assertEqual(result.examined["deps.dev"].with_data, 1)
        self.assertNotEqual(result.exit_code, 2)  # every source answered
        cdx = next(c for c in bom.build(result)["components"] if c["name"] == "transformers")
        self.assertEqual(cdx["licenses"], [{"license": {"id": "Apache-2.0", "acknowledgement": "declared"}}])

    def test_no_registry_also_keeps_package_names_from_deps_dev(self):
        fetch = Fetch(ANSWERS)
        result = self.scan(fetch, registry=False)
        self.assertEqual([u for u in fetch.urls if u.startswith(DEPS_DEV)], [])
        self.assertEqual(result.examined["deps.dev"].skipped, "disabled (--no-registry)")

    def test_a_failed_deps_dev_lookup_makes_the_scan_incomplete(self):
        fetch = Fetch(ANSWERS, fail={DEPS_DEV + "PYPI/packages/transformers/versions/4.44.0"})
        result = self.scan(fetch)
        self.assertEqual(result.examined["deps.dev"].errors, 1)
        self.assertEqual(result.exit_code, 2)


if __name__ == "__main__":
    unittest.main()
