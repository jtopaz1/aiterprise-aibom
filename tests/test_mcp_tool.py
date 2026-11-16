"""The MCP tool `scan_ai_supply_chain` as a caller of the gated scan (the gate itself: test_gate.py)."""

import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import credentials, mcpserver, net, policy, secdb

# one high, non-malicious finding (ait.mcp.cmd.privilege.sudo): enough to fail the default gate
CONFIG = {"mcpServers": {"admin": {"command": "sudo", "args": ["python", "server.py"]}}}
KEY = "aik_live_" + "A" * 36


class McpToolTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "project"
        self.root.mkdir()
        (self.root / ".mcp.json").write_text(json.dumps(CONFIG), encoding="utf-8")
        env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": str(Path(tmp.name) / "home")})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("AITERPRISE_API_KEY", None)

    def scan(self, **arguments):
        return mcpserver.scan_tool({"path": str(self.root), "offline": True, **arguments})

    def test_the_tool_goes_through_the_gate(self):
        out, is_error = self.scan()
        self.assertFalse(is_error)
        self.assertEqual((out["exit_code"], [f["rule_id"] for f in out["findings"]]),
                         (1, ["ait.mcp.cmd.privilege.sudo"]))
        until = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        policy.add_local_suppression(self.root, out["findings"][0]["fingerprint"], until, "accepted for this test")
        out, _ = self.scan()
        self.assertEqual((out["exit_code"], out["findings"]), (0, []))
        self.assertEqual(self.scan(fail_on="none")[0]["exit_code"], 0)

    def test_a_policy_that_does_not_load_is_an_error_not_a_pass(self):
        (self.root / "aibom.policy.yaml").write_text("version: 1\nuse_context: banana\n", encoding="utf-8")
        out, is_error = self.scan()
        self.assertTrue(is_error)
        self.assertIn("use_context", out["error"])

    def test_the_tool_never_spends_the_secdb_budget_and_says_so(self):
        credentials.save_api_key(KEY)  # logged in: the CLI would consult SecDB
        with mock.patch.object(net, "request", side_effect=AssertionError("no network in tests")), \
                mock.patch.object(secdb, "enrich", return_value=[]) as enrich:
            out, _ = self.scan(offline=False)
        enrich.assert_not_called()
        self.assertEqual(out["examined"]["secdb"]["skipped"], "not consulted by the MCP tool")


if __name__ == "__main__":
    unittest.main()
