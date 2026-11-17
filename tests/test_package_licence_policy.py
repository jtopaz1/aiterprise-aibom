"""Package licences against the policy: `deny_package_licences` and `allow_package_licences`,
SPDX expressions read as SPDX means them (OR is a choice, AND needs both)."""

import json
import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import policy, sources
from aiterprise_scan.cache import Cache
from aiterprise_scan.model import Component, Location, ScanResult
from aiterprise_scan.scanner import ScanOptions, run_scan


def lib(name, licence=None, eco="npm"):
    comp = Component(name=name, ctype="library", version="1.0.0", ecosystem=eco,
                     locations=[Location("package-lock.json", 1)], source="package-lock")
    comp.licence = licence
    return comp


def verdict(expr, allow=(), deny=()):
    return policy.licence_verdict(expr, [a.lower() for a in allow], [d.lower() for d in deny])


class ParseTests(unittest.TestCase):
    def test_the_lists_are_known_keys_kept_lower_case(self):
        pol = policy.parse_policy({"allow_package_licences": ["MIT", "Apache-2.0"],
                                   "deny_package_licences": "AGPL-3.0"})
        self.assertEqual((pol.errors, pol.warnings), ([], []))
        self.assertEqual(pol.allow_package_licences, ["mit", "apache-2.0"])
        self.assertEqual(pol.deny_package_licences, ["agpl-3.0"])

    def test_a_mapping_is_an_error(self):
        pol = policy.parse_policy({"deny_package_licences": {"agpl": 1}})
        self.assertEqual(pol.errors, ["deny_package_licences: expected a list"])


class ExpressionTests(unittest.TestCase):
    def test_a_bare_family_covers_only_and_or_later(self):
        for lic in ("AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-3.0+", "AGPL-3.0", "agpl-3.0-only"):
            self.assertEqual(verdict(lic, deny=["AGPL-3.0"]), ("denied", "agpl-3.0"), lic)
        self.assertEqual(verdict("LGPL-3.0-only", deny=["GPL-3.0"]), (None, None))

    def test_only_and_or_later_are_told_apart(self):
        self.assertEqual(verdict("GPL-3.0", deny=["GPL-3.0-only"])[0], "denied")  # the deprecated bare id is -only
        self.assertEqual(verdict("GPL-3.0-or-later", deny=["GPL-3.0-only"])[0], None)
        self.assertEqual(verdict("GPL-3.0+", deny=["GPL-3.0-or-later"])[0], "denied")

    def test_patterns_are_globs(self):
        self.assertEqual(verdict("GPL-2.0-only", deny=["GPL-*"]), ("denied", "gpl-*"))
        self.assertEqual(verdict("LGPL-2.1-only", deny=["GPL-*"])[0], None)

    def test_or_is_a_choice_and_needs_both(self):
        self.assertEqual(verdict("MIT OR AGPL-3.0-only", deny=["AGPL-3.0"])[0], None)
        self.assertEqual(verdict("MIT AND AGPL-3.0-only", deny=["AGPL-3.0"])[0], "denied")
        self.assertEqual(verdict("(MIT OR AGPL-3.0-only) AND GPL-2.0-only", deny=["AGPL-3.0", "GPL-2.0"])[0], "denied")
        self.assertEqual(verdict("(AGPL-3.0-only OR GPL-2.0-only) AND MIT", deny=["AGPL-3.0", "GPL-2.0"])[0], "denied")
        self.assertEqual(verdict("mit or agpl-3.0-only", deny=["AGPL-3.0"])[0], None)  # operators in any case

    def test_an_exception_keeps_the_licence_it_is_attached_to(self):
        self.assertEqual(verdict("GPL-2.0-only WITH Classpath-exception-2.0", deny=["GPL-2.0"])[0], "denied")
        self.assertEqual(verdict("GPL-2.0-only WITH Classpath-exception-2.0", allow=["GPL-2.0"])[0], None)
        self.assertEqual(verdict("GPL-2.0-only WITH Classpath-exception-2.0",
                                 allow=["GPL-2.0-only WITH Classpath-exception-2.0"])[0], None)

    def test_the_allow_list(self):
        allow = ["MIT", "Apache-2.0"]
        for lic in ("MIT", "Apache-2.0", "MIT OR GPL-3.0-only", "(MIT AND Apache-2.0)", "mit or apache-2.0"):
            self.assertEqual(verdict(lic, allow=allow), (None, None), lic)
        for lic in ("MIT AND GPL-3.0-only", "BSD-3-Clause", "SEE LICENSE IN LICENSE.md", "UNLICENSED", "(MIT",
                    "MIT License"):  # free text is not read as the SPDX id it starts with
            self.assertEqual(verdict(lic, allow=allow), ("not-allowed", None), lic)

    def test_denied_wins_over_allowed(self):
        self.assertEqual(verdict("AGPL-3.0-only", allow=["*"], deny=["AGPL-3.0"])[0], "denied")

    def test_no_lists_no_verdict(self):
        self.assertEqual(verdict("AGPL-3.0-only"), (None, None))


class FindingTests(unittest.TestCase):
    POLICY = {"deny_package_licences": ["AGPL-3.0"], "allow_package_licences": ["MIT", "Apache-2.0"]}

    def components(self):
        model = Component(name="org/model", ctype="model", ecosystem="huggingface")
        model.licence = "cc-by-nc-4.0"  # judged by allow/deny_model_licences, never here
        return [lib("axios", "MIT"), lib("copyleft", "AGPL-3.0-only"), lib("bsd", "BSD-3-Clause"),
                lib("dual", "MIT OR AGPL-3.0-only"), lib("unknown"), model]

    def test_denied_and_not_allowed_licences(self):
        result = ScanResult(target="t", mode="offline")
        out = policy.package_policy_findings(self.components(), policy.parse_policy(self.POLICY, "p.yaml"), result)
        got = {(f.component.name, f.rule_id, f.severity) for f in out}
        self.assertEqual(got, {("copyleft", "ait.policy.denied-licence", "high"),
                               ("bsd", "ait.policy.licence-not-allowed", "medium")})
        denied = next(f for f in out if f.rule_id == "ait.policy.denied-licence")
        self.assertIn("AGPL-3.0-only", denied.title)
        self.assertEqual(denied.evidence[0].detail,
                         {"policy": "p.yaml", "list": "deny_package_licences", "matched": "agpl-3.0",
                          "licence": "AGPL-3.0-only"})
        self.assertEqual(denied.verdict, "suspicious")
        self.assertEqual(sources.for_rule(denied.rule_id), ("policy",))
        # five packages judged, two flagged; the model is not a package
        ex = result.examined[sources.POLICY.name]
        self.assertEqual((ex.checked, ex.with_data), (5, 2))
        self.assertEqual([n for n in result.notes if n.startswith("policy:")],
                         ["policy: 1 package(s) have no known licence, so allow_package_licences could not be "
                          "checked for them: unknown"])

    def test_deny_packages_and_licence_lists_count_once(self):
        doc = {**self.POLICY, "deny_packages": ["pkg:npm/axios"]}
        result = ScanResult(target="t", mode="offline")
        out = policy.package_policy_findings(self.components(), policy.parse_policy(doc), result)
        self.assertEqual(sorted(f.rule_id for f in out),
                         ["ait.policy.denied-licence", "ait.policy.denied-package", "ait.policy.licence-not-allowed"])
        ex = result.examined[sources.POLICY.name]
        self.assertEqual((ex.checked, ex.with_data), (5, 3))

    def test_a_deny_list_alone_says_nothing_about_unknown_licences(self):
        result = ScanResult(target="t", mode="offline")
        policy.package_policy_findings(self.components(), policy.parse_policy({"deny_package_licences": ["AGPL-3.0"]}),
                                       result)
        self.assertEqual([n for n in result.notes if n.startswith("policy:")], [])

    def test_no_lists_no_source(self):
        result = ScanResult(target="t", mode="offline")
        self.assertEqual(policy.package_policy_findings(self.components(), policy.Policy(), result), [])
        self.assertNotIn(sources.POLICY.name, result.examined)


class ScanTests(unittest.TestCase):
    def test_a_scan_flags_a_lockfile_package_under_a_denied_licence(self):
        lock = {"name": "app", "lockfileVersion": 3, "packages": {
            "": {"name": "app", "dependencies": {"ok": "1.0.0", "bad": "2.0.0"}},
            "node_modules/ok": {"version": "1.0.0", "license": "MIT"},
            "node_modules/bad": {"version": "2.0.0"},
        }}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            pol = policy.parse_policy({"deny_package_licences": ["MIT"]})
            result = run_scan(ScanOptions(target=root, offline=True, cache=Cache(enabled=False), policy=pol))
        hits = [(f.rule_id, f.component.name) for f in result.findings if f.rule_id.startswith("ait.policy.")]
        self.assertEqual(hits, [("ait.policy.denied-licence", "ok")])  # "bad" records no licence


if __name__ == "__main__":
    unittest.main()
