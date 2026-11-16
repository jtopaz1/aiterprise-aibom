"""The MCP tool gates a scan exactly as the CLI does: same policy, same suppressions, same baseline."""

import contextlib
import datetime as dt
import io
import json
import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import cli, mcpserver, policy

# one high, non-malicious finding (ait.mcp.cmd.privilege.sudo): enough to fail the default gate
CONFIG = {"mcpServers": {"admin": {"command": "sudo", "args": ["python", "server.py"]}}}


class McpToolGateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / ".mcp.json").write_text(json.dumps(CONFIG), encoding="utf-8")

    def scan(self, **arguments):
        return mcpserver.scan_tool({"path": str(self.root), "offline": True, **arguments})

    def write_policy(self, text):
        (self.root / "aibom.policy.yaml").write_text(text, encoding="utf-8")

    def test_the_planted_config_fails_the_gate(self):
        out, is_error = self.scan()
        self.assertFalse(is_error)
        self.assertEqual(out["exit_code"], 1)
        self.assertEqual([f["rule_id"] for f in out["findings"]], ["ait.mcp.cmd.privilege.sudo"])

    def test_a_suppression_made_in_the_ui_is_honoured(self):
        fingerprint = self.scan()[0]["findings"][0]["fingerprint"]
        until = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        policy.add_local_suppression(self.root, fingerprint, until, "accepted for this test")
        out, _ = self.scan()
        self.assertEqual((out["exit_code"], out["findings"]), (0, []))

    def test_the_policy_baseline_is_honoured(self):
        self.write_policy("version: 1\nbaseline: .aiterprise/baseline.json\n")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["scan", str(self.root), "--offline", "--write-baseline",
                      str(self.root / ".aiterprise" / "baseline.json")])
        out, _ = self.scan()
        self.assertEqual((out["exit_code"], out["findings"]), (0, []))

    def test_a_policy_that_does_not_load_is_an_error_not_a_pass(self):
        self.write_policy("version: 1\nuse_context: banana\n")
        out, is_error = self.scan()
        self.assertTrue(is_error)
        self.assertIn("use_context", out["error"])

    def test_the_policy_decides_the_threshold_unless_the_caller_names_one(self):
        self.write_policy("version: 1\nfail_on: [critical]\n")
        self.assertEqual(self.scan()[0]["exit_code"], 0)
        self.assertEqual(self.scan(fail_on="high")[0]["exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
