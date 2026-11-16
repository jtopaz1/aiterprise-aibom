"""The gated scan: a scan under the project's policy, suppressions and baseline, exit code decided.

Every caller (CLI, MCP tool, UI) goes through `gate.gated_scan`, so the rules of the gate are
tested here once, on temporary directories and offline."""

import contextlib
import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import credentials, gate, mcp, net, policy, secdb
from aiterprise_scan.cache import Cache
from aiterprise_scan.scanner import ScanOptions

# one high, non-malicious finding: enough to fail the default gate (critical, high)
CONFIG = {"mcpServers": {"admin": {"command": "sudo", "args": ["python", "server.py"]}}}
RULE = "ait.mcp.cmd.privilege.sudo"
KEY = "aik_live_" + "A" * 36
MALICIOUS_BOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
    {"type": "library", "name": "litellm", "version": "1.82.7", "purl": "pkg:pypi/litellm@1.82.7"}]}


@contextlib.contextmanager
def working_directory(path):
    before = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(before)


class GatedScanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.root = self.tmp / "project"
        self.root.mkdir()
        (self.root / ".mcp.json").write_text(json.dumps(CONFIG), encoding="utf-8")
        # an empty home: no SecDB credential, and nothing is read from the developer's own
        env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": str(self.tmp / "home")})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("AITERPRISE_API_KEY", None)

    def scan(self, overrides=None, **options):
        options.setdefault("target", self.root)
        options.setdefault("offline", True)
        return gate.gated_scan(ScanOptions(cache=Cache(enabled=False), **options), overrides)

    def active(self, result):
        return [f.rule_id for f in result.findings if f.status == "new"]

    def write_policy(self, text, directory=None):
        path = (directory or self.root) / "aibom.policy.yaml"
        path.write_text(text, encoding="utf-8")
        return path

    def write_baseline(self, path=None):
        path = path or self.root / ".aiterprise" / "baseline.json"
        policy.write_baseline(self.scan(), path)
        return path

    # ---- the gate ------------------------------------------------------------------------
    def test_a_finding_at_the_threshold_fails_the_gate(self):
        result = self.scan()
        self.assertEqual((result.exit_code, self.active(result)), (1, [RULE]))

    def test_a_suppression_made_in_the_ui_is_honoured(self):
        fingerprint = self.scan().findings[0].fingerprint
        until = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        policy.add_local_suppression(self.root, fingerprint, until, "accepted for this test")
        result = self.scan()
        self.assertEqual((result.exit_code, self.active(result)), (0, []))
        self.assertEqual(result.findings[0].status, "suppressed")

    def test_the_policy_decides_the_threshold_unless_the_caller_names_one(self):
        self.write_policy("version: 1\nfail_on: [critical]\n")
        self.assertEqual(self.scan().exit_code, 0)
        self.assertEqual(self.scan(gate.GateOverrides(fail_on="high")).exit_code, 1)
        self.assertEqual(self.scan(gate.GateOverrides(fail_on="none")).exit_code, 0)

    def test_a_policy_failure_outranks_an_incomplete_scan(self):
        with mock.patch("aiterprise_scan.secrets.scan_secrets", side_effect=RuntimeError("boom")):
            self.assertEqual(self.scan().exit_code, 1)
            self.assertEqual(self.scan(gate.GateOverrides(fail_on="none")).exit_code, 2)

    def test_the_caller_cannot_bring_its_own_policy(self):
        permissive = policy.Policy(fail_on=set())
        self.assertEqual(self.scan(policy=permissive).exit_code, 1)

    # ---- the baseline --------------------------------------------------------------------
    def test_the_policy_baseline_is_honoured_for_a_directory(self):
        self.write_policy("version: 1\nbaseline: .aiterprise/baseline.json\n")
        self.write_baseline()
        result = self.scan()
        self.assertEqual((result.exit_code, self.active(result)), (0, []))

    def test_the_policy_baseline_is_honoured_for_a_single_file(self):
        self.write_policy("version: 1\nbaseline: .aiterprise/baseline.json\n")
        self.write_baseline()
        result = self.scan(target=self.root / ".mcp.json")
        self.assertEqual((result.exit_code, self.active(result)), (0, []))

    def test_a_baseline_file_named_by_the_caller_is_used(self):
        elsewhere = self.write_baseline(self.tmp / "elsewhere" / "accepted.json")
        self.assertEqual(self.scan().exit_code, 1)
        self.assertEqual(self.scan(gate.GateOverrides(baseline_file=elsewhere)).exit_code, 0)

    def test_a_policy_file_elsewhere_still_takes_its_baseline_from_the_scanned_directory(self):
        other = self.tmp / "ci"
        other.mkdir()
        named = self.write_policy("version: 1\nbaseline: .aiterprise/baseline.json\n", other)
        self.write_baseline()  # in the project, not next to the policy file
        self.assertEqual(self.scan(gate.GateOverrides(policy_file=named)).exit_code, 0)

    # ---- a policy that does not load -----------------------------------------------------
    def test_a_policy_that_does_not_load_raises_before_anything_is_scanned(self):
        self.write_policy("version: 1\nuse_context: banana\n")
        with mock.patch.object(gate, "run_scan") as run_scan, self.assertRaises(gate.PolicyError) as caught:
            self.scan()
        run_scan.assert_not_called()
        self.assertIn("use_context", str(caught.exception))

    def test_a_suppressions_file_that_does_not_parse_raises(self):
        local = self.root / ".aiterprise" / "suppressions.json"
        local.parent.mkdir()
        local.write_text("{not json", encoding="utf-8")
        with self.assertRaises(gate.PolicyError) as caught:
            self.scan()
        self.assertIn("suppressions.json", str(caught.exception))

    def test_policy_warnings_are_notes_on_the_result(self):
        self.write_policy("version: 1\nextra: 1\n")
        notes = self.scan().notes
        self.assertTrue(any("unknown key 'extra'" in note and "aibom.policy.yaml" in note for note in notes), notes)

    # ---- where the policy comes from -----------------------------------------------------
    def test_a_scan_of_this_machine_only_looks_up_no_policy(self):
        self.write_policy("version: 1\nfail_on: [critical]\n")
        with (working_directory(self.root),
              mock.patch.object(mcp, "machine_agent_config_paths", return_value=[self.root / ".mcp.json"])):
            result = self.scan(target=None, agent_configs=True, mcp_only=True)
        self.assertEqual((result.exit_code, result.policy_path), (1, None))

    def test_a_scan_of_a_bom_alone_uses_the_policy_of_the_current_directory(self):
        bom = self.tmp / "third-party.cdx.json"
        bom.write_text(json.dumps(MALICIOUS_BOM), encoding="utf-8")
        self.write_policy("version: 1\nfail_on: []\n")
        with working_directory(self.root):
            result = self.scan(target=None, boms=[bom])
        self.assertIn("ait.pkg.malicious", self.active(result))
        self.assertEqual(result.exit_code, 0)

    # ---- SecDB ---------------------------------------------------------------------------
    def online(self, overrides=None):
        with mock.patch.object(net, "request", side_effect=AssertionError("no network in tests")):
            return self.scan(overrides, offline=False)

    def test_without_a_credential_secdb_is_reported_as_skipped(self):
        self.assertEqual(self.online().examined["secdb"].skipped, "not logged in (aiterprise-scan login)")

    def test_a_caller_that_declines_secdb_has_its_reason_reported(self):
        credentials.save_api_key(KEY)
        with mock.patch.object(secdb, "enrich", return_value=[]) as enrich:
            result = self.online(gate.GateOverrides(skip_secdb="not consulted by the MCP tool"))
        enrich.assert_not_called()
        self.assertEqual(result.examined["secdb"].skipped, "not consulted by the MCP tool")

    def test_with_a_credential_secdb_is_consulted(self):
        credentials.save_api_key(KEY)
        with mock.patch.object(secdb, "enrich", return_value=[]) as enrich:
            self.online()
        enrich.assert_called_once()


if __name__ == "__main__":
    unittest.main()
