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


class PyPIPageTests(unittest.TestCase):
    """The README is the PyPI description: PyPI resolves no relative link or image in it."""

    def test_readme_links_and_images_are_absolute(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        targets = re.findall(r"\]\(\s*<?([^)\s>]+)", readme) + re.findall(r"""(?:src|href)\s*=\s*["']([^"']+)""",
                                                                            readme)
        relative = [t for t in targets if not re.match(r"(https?://|mailto:|#)", t)]
        self.assertEqual(relative, [])
        self.assertTrue(targets, "no links found: the pattern no longer reads the README")
        # a link into this repository names a file or folder that exists on main
        repo = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))["repository"]["url"]
        owner_repo = repo.removeprefix("https://github.com/")
        ours = [m.group(1) for t in targets
                for m in [re.match(re.escape(repo) + r"/(?:blob|tree)/main/([^#?]+)", t)
                          or re.match(r"https://raw\.githubusercontent\.com/" + re.escape(owner_repo) + r"/main/([^#?]+)", t)]
                if m]
        self.assertTrue(ours, "no links into the repository found")
        self.assertEqual([p for p in ours if not (ROOT / p).exists()], [])


class PackageMetadataTests(unittest.TestCase):
    def setUp(self):
        import tomllib

        self.pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.project = self.pyproject["project"]

    def test_the_build_backend_understands_a_licence_expression(self):
        # PEP 639 (`license = "Apache-2.0"`, `license-files`) is read by setuptools 77 and later only;
        # an older one refuses the pyproject, so a lower floor lets a packager's build fail
        if not (isinstance(self.project.get("license"), str) or "license-files" in self.project):
            self.skipTest("no PEP 639 fields")
        floors = [re.fullmatch(r"setuptools\s*>=\s*(\d+)(?:\.\d+)*", r) for r in self.pyproject["build-system"]["requires"]]
        floor = next(int(m.group(1)) for m in floors if m)
        self.assertGreaterEqual(floor, 77)

    def test_project_urls_point_at_the_repository(self):
        repo = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))["repository"]["url"]
        urls = self.project.get("urls", {})
        self.assertEqual(urls.get("Source"), repo)
        self.assertEqual(urls.get("Issues"), repo + "/issues")
        for name, url in urls.items():
            self.assertTrue(url.startswith(repo + "/") or url == repo, (name, url))

    def test_classifiers_name_only_the_pythons_ci_runs(self):
        named = sorted(c.rsplit(":: ", 1)[1] for c in self.project["classifiers"]
                       if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c))
        self.assertTrue(named, "no Python version classifiers")
        floor = re.fullmatch(r">=\s*(3\.\d+)", self.project["requires-python"]).group(1)
        self.assertEqual(min(named, key=lambda v: int(v.split(".")[1])), floor)
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for version in named:
            self.assertIn(f'"{version}"', ci, f"Python {version} is classified but no CI job runs it")


if __name__ == "__main__":
    unittest.main()
