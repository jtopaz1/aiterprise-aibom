"""Release hygiene that CI also runs: the licence check, and the MCP registry manifest."""

import importlib.util
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_licences", ROOT / "tools" / "check_licences.py")
check_licences = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_licences)


class LicenceCheckTests(unittest.TestCase):
    def test_repository_passes(self):
        self.assertEqual(check_licences.problems(), [])

    def test_unattributed_data_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy(ROOT / "pyproject.toml", root / "pyproject.toml")
            shutil.copy(ROOT / "NOTICE", root / "NOTICE")
            shutil.copytree(ROOT / "src" / "aiterprise_scan" / "data", root / "src" / "aiterprise_scan" / "data")
            (root / "src" / "aiterprise_scan" / "data" / "ait" / "mystery.json").write_text("{}", encoding="utf-8")
            self.assertTrue(any("mystery.json" in p for p in check_licences.problems(root)))


class McpRegistryManifestTests(unittest.TestCase):
    def test_server_json_matches_the_package(self):
        from aiterprise_scan import __version__

        doc = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], __version__)
        pkg = doc["packages"][0]
        self.assertEqual((pkg["registryType"], pkg["identifier"], pkg["version"]), ("pypi", "aiterprise-scan",
                                                                                   __version__))
        self.assertEqual([a["value"] for a in pkg["packageArguments"]], ["mcp", "serve"])
        # the registry verifies PyPI ownership by this marker in the README (the PyPI description)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(readme, r"mcp-name: " + re.escape(doc["name"]) + r"(\s|-->)")

    def test_server_json_fits_the_registry_schema_limits(self):
        # server.schema.json 2025-12-11: the registry refuses a manifest outside these limits
        doc = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        self.assertRegex(doc["name"], r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")
        self.assertLessEqual(len(doc["name"]), 200)
        self.assertTrue(1 <= len(doc["description"]) <= 100, f"description is {len(doc['description'])} characters")
        self.assertLessEqual(len(doc.get("title", "")), 100)
        self.assertLessEqual(len(doc["version"]), 255)


if __name__ == "__main__":
    unittest.main()
