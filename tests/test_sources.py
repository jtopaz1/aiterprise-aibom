"""Sources: each is named once in sources.py, and each counts its own coverage (GLOSSARY.md)."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import cli, ingest, licences, mcp, modelfiles, policy, providers, skills, sources, walk
from aiterprise_scan.model import Component, Location, ScanResult

GOLDEN = Path(__file__).parent / "golden"
# GLOBAL os system / BINUNICODE "echo pwned" / TUPLE1 / REDUCE / STOP: inert bytes, never loaded
MALICIOUS_PICKLE = b"\x80\x02cos\nsystem\nq\x00X\x0a\x00\x00\x00echo pwnedq\x01\x85q\x02Rq\x03."


def new_result():
    return ScanResult("repo", "offline")


def coverage(result, source):
    entry = result.examined[source.name]
    return entry.checked, entry.with_data


class DeclarationTests(unittest.TestCase):
    def test_every_coverage_name_a_scan_writes_is_a_declared_source(self):
        declared = {s.name for s in sources.ALL} | set(providers.REGISTRY)
        for fixture in sorted(p for p in GOLDEN.iterdir() if p.is_dir()):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                cli.main(["scan", str(fixture), "--offline", "--format", "json"])
            with self.subTest(fixture=fixture.name):
                self.assertLessEqual(set(json.loads(out.getvalue())["examined"]), declared)

    def test_no_two_sources_share_a_name(self):
        names = [s.name for s in sources.ALL]
        self.assertEqual(len(names), len(set(names)))

    def test_the_sources_consulted_for_each_rule_family(self):
        expected = {
            "ait.pkg.malicious": ("ait-malicious", "osv", "osv-subset", "registry", "archives", "secdb"),
            "ait.vuln.advisory": ("osv", "osv-subset", "kev"),
            "ait.model.pickle.dangerous-global": ("model-files", "archives", "secdb"),
            "ait.mcp.cmd.privilege.sudo": ("mcp", "archives", "secdb"),
            "ait.skill.risk-score": ("skills",),
            "ait.licence.unknown": ("licences",),
            "ait.secret.openai": ("secrets",),
            "ait.archive.path-traversal": ("archives",),
            "ait.policy.denied-package": ("policy",),
            "ait.unheard-of.rule": (),
        }
        for rule_id, names in expected.items():
            with self.subTest(rule=rule_id):
                self.assertEqual(sources.for_rule(rule_id), names)


class SelfCountingTests(unittest.TestCase):
    """A source asked directly, with a result to write to, records its own coverage."""

    def test_skills(self):
        root = GOLDEN / "F09-malicious-skill"
        result = new_result()
        components, findings = skills.analyze_skills(root, walk.walk(root), result)
        self.assertTrue(findings)
        self.assertEqual(coverage(result, sources.SKILLS), (len(components), 1))

    def test_mcp_configs_of_a_project(self):
        root = GOLDEN / "F03-poisoned-mcp"
        result = new_result()
        components, findings = mcp.analyze_mcp(root, walk.walk(root, all_files=True), result=result)
        servers = [c for c in components if c.ctype == "mcp-server"]
        self.assertTrue(findings)
        self.assertEqual(coverage(result, sources.MCP)[0], len(servers))
        self.assertGreaterEqual(coverage(result, sources.MCP)[1], 1)

    def test_mcp_configs_of_this_machine(self):
        config = GOLDEN / "F04-curl-bash-mcp" / ".mcp.json"
        result = new_result()
        with mock.patch.object(mcp, "machine_agent_config_paths", return_value=[config]):
            components, findings = mcp.analyze_machine_configs(result)
        self.assertTrue(findings)
        self.assertEqual(coverage(result, sources.MCP), (1, 1))

    def test_licences(self):
        model = Component("meta-llama/Meta-Llama-3-8B", ctype="model", ecosystem="huggingface", licence="llama3",
                          locations=[Location("app.py", 2)], source="code-ref")
        library = Component("requests", ecosystem="pypi", version="2.32.3")
        result = new_result()
        findings = licences.judge_licences([model, library], "commercial", result=result)
        self.assertTrue(findings)
        self.assertEqual(coverage(result, sources.LICENCES), (1, 1))  # the library is not judged for a licence

    def test_the_deny_list(self):
        requests = Component("requests", ecosystem="pypi", version="2.32.3")
        other = Component("urllib3", ecosystem="pypi", version="2.2.0")
        denying = policy.parse_policy({"deny_packages": ["pkg:pypi/requests@2.32.3"]})
        result = new_result()
        findings = policy.package_policy_findings([requests, other], denying, result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(coverage(result, sources.POLICY), (2, 1))

    def test_no_deny_list_is_not_a_consulted_source(self):
        result = new_result()
        self.assertEqual(policy.package_policy_findings([Component("requests", ecosystem="pypi")],
                                                         policy.Policy(), result), [])
        self.assertNotIn(sources.POLICY.name, result.examined)

    def test_model_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "model.pkl").write_bytes(MALICIOUS_PICKLE)
            (root / "notes.txt").write_text("not a model", encoding="utf-8")
            result = new_result()
            components, findings = modelfiles.analyze(root, sorted(root.iterdir()), result)
        self.assertEqual(len(components), 1)
        self.assertTrue(findings)
        self.assertEqual(coverage(result, sources.MODEL_FILES), (1, 1))

    def test_bom_files(self):
        root = GOLDEN / "F08-cdxgen-bom"
        result = new_result()
        components, failed = ingest.ingest_boms([root / "bom.json"], root, result, explicit=True)
        self.assertTrue(components)
        self.assertFalse(failed)
        self.assertEqual(coverage(result, sources.BOM_INGEST), (1, 1))

    def test_a_bom_named_by_the_user_that_is_not_a_bom_fails_and_is_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "not-a-bom.json"
            bad.write_text('{"hello": "world"}', encoding="utf-8")
            named, found = new_result(), new_result()
            self.assertEqual(ingest.ingest_boms([bad], Path(tmp), named, explicit=True), ([], True))
            self.assertEqual(ingest.ingest_boms([bad], Path(tmp), found, explicit=False), ([], False))
        self.assertTrue(any(note.startswith("bom:") for note in named.notes))
        self.assertEqual(found.notes, [])
        self.assertNotIn(sources.BOM_INGEST.name, named.examined)

    def test_asked_without_a_result_a_source_only_answers(self):
        root = GOLDEN / "F09-malicious-skill"
        components, findings = skills.analyze_skills(root, walk.walk(root))
        self.assertTrue(components and findings)


if __name__ == "__main__":
    unittest.main()
