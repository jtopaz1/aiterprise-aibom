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


class ReleasedDocsTests(unittest.TestCase):
    """What the docs tell people to install and pin matches the version being released."""

    DOCS = ("README.md", "docs/index.md", "docs/quickstart.md", "docs/integrations.md")

    def _read(self, name):
        return (ROOT / name).read_text(encoding="utf-8")

    def test_the_action_and_the_hook_are_pinned_to_this_release(self):
        from aiterprise_scan import __version__

        pins = []
        for name in self.DOCS:
            text = self._read(name)
            pins += [(name, "action", m) for m in re.findall(r"uses:\s*jtopaz1/aiterprise-aibom/action@(\S+)", text)]
            hook = re.findall(r"repo:\s*https://github\.com/jtopaz1/aiterprise-aibom\s*\n\s*rev:\s*(\S+)", text)
            pins += [(name, "pre-commit", m) for m in hook]
        self.assertGreaterEqual(len([p for p in pins if p[1] == "action"]), 2, pins)
        self.assertGreaterEqual(len([p for p in pins if p[1] == "pre-commit"]), 3, pins)
        self.assertEqual([p for p in pins if p[2] != f"v{__version__}"], [])

    def test_the_docs_no_longer_say_it_is_unreleased(self):
        for name in self.DOCS:
            text = self._read(name)
            self.assertNotRegex(text, r"(?i)not released yet|nothing is published|with the first tagged release", name)


class DistChecksRunTests(unittest.TestCase):
    """What PyPI gets is checked on every pull request, and again by the release before the upload."""

    def _steps(self, workflow, job):
        text = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
        body = re.search(rf"^  {job}:\n(.*?)(?=^  \S|\Z)", text, re.MULTILINE | re.DOTALL).group(1)
        return [line.strip() for line in body.splitlines()]

    def test_every_pull_request_checks_the_dist(self):
        steps = self._steps("ci.yml", "wheel")
        self.assertIn("python -m twine check --strict dist/*", steps)
        self.assertIn("python tools/check_dist.py dist", steps)

    def test_the_release_checks_the_dist_right_after_building_it(self):
        steps = self._steps("release.yml", "dist")
        build = steps.index("python -m build")
        self.assertEqual(steps.index("python -m twine check --strict dist/*"), build + 4)
        self.assertEqual(steps.index("python tools/check_dist.py dist --release"), build + 5)
        self.assertIn("needs: sign", self._steps("release.yml", "pypi"))
        self.assertIn("needs: [dist, binaries]", self._steps("release.yml", "sign"))


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
