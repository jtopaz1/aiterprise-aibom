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


PYPI_SWITCH = "if: vars.PUBLISH_TO_PYPI == 'true'"


class PyPIOptInTests(unittest.TestCase):
    """The project has no PyPI account: publishing there is off until the owner sets PUBLISH_TO_PYPI."""

    def test_a_release_uploads_to_pypi_only_when_switched_on(self):
        job = DistChecksRunTests()._steps("release.yml", "pypi")
        self.assertIn(PYPI_SWITCH, job)
        self.assertIn("needs: sign", job)

    def test_the_gitlab_template_installs_the_release_wheel_not_pypi(self):
        from aiterprise_scan import __version__ as v

        from aiterprise_scan import miniyaml

        text = (ROOT / "templates" / "gitlab" / "aiterprise-scan.gitlab-ci.yml").read_text(encoding="utf-8")
        install = miniyaml.load(text)["aiterprise-scan"]["variables"]["AIBOM_INSTALL"]
        self.assertEqual(install, "https://github.com/jtopaz1/aiterprise-aibom/releases/download/"
                                  f"v{v}/aiterprise_scan-{v}-py3-none-any.whl")
        self.assertNotIn("until the first PyPI release", text)
        self.assertNotRegex((ROOT / "docs" / "integrations.md").read_text(encoding="utf-8"),
                            r"(?i)until the first PyPI release")


class PublishedChannelsTests(unittest.TestCase):
    """What the docs tell people to install is what was published, and published.yml installs each of
    those from where it was published and holds it to the killer demo."""

    REPO = "https://github.com/jtopaz1/aiterprise-aibom"
    WORKFLOWS = ROOT / ".github" / "workflows"
    WORKFLOW = WORKFLOWS / "published.yml"

    def _docs(self):
        return {name: (ROOT / name).read_text(encoding="utf-8") for name in ReleasedDocsTests.DOCS}

    def _job(self, name):
        text = self.WORKFLOW.read_text(encoding="utf-8")
        found = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(found, f"published.yml has no job {name}")
        return found.group(1)

    def test_the_docs_install_only_what_was_published(self):
        from aiterprise_scan import __version__ as v

        docs = self._docs()
        # PyPI refused the v0.1.0 upload (RELEASING.md): until PyPI has a release, no doc offers it
        allowed = {".", "-e .", f"git+{self.REPO}@v{v}"}
        installs = [(name, m) for name, text in docs.items()
                    for m in re.findall(r"\bpipx? install\s+((?:-e\s+)?[^\s`#)]+)", text)]
        self.assertTrue([i for i in installs if i[1].startswith("git+")], installs)
        self.assertEqual([i for i in installs if i[1] not in allowed], [])
        self.assertEqual([n for n, t in docs.items() if re.search(r"\buvx\b", t)], [])
        images = [(name, tag) for name, text in docs.items()
                  for tag in re.findall(r"ghcr\.io/jtopaz1/aiterprise-scan(?::([\w.-]+))?", text)]
        self.assertTrue(images)
        self.assertEqual([i for i in images if i[1] not in ("", "latest", v)], [])
        releases = [(name, tag) for name, text in docs.items()
                    for tag in re.findall(re.escape(self.REPO) + r"/releases/tag/(\S+?)[)\s]", text)]
        self.assertTrue(releases)
        self.assertEqual([r for r in releases if r[1] != f"v{v}"], [])

    def test_it_runs_by_hand_weekly_and_when_it_changes(self):
        text = self.WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^on:\n  workflow_dispatch:\n  schedule:\n    - cron: ")
        self.assertRegex(text, r"(?m)^  pull_request:\n    paths: \[\.github/workflows/published\.yml\]$")
        self.assertNotRegex(text, r"(?m)^  push:")

    def test_each_channel_is_installed_from_where_it_was_published_and_runs_the_killer_demo(self):
        pip = self._job("pip-from-the-tag")
        self.assertIn('pip install --quiet "git+https://github.com/${REPO}@v${V}"', pip)
        self.assertIn('python-version: "3.11"', pip)   # the floor the docs give
        image = self._job("image")
        self.assertIn('for tag in "$V" latest; do', image)
        self.assertNotIn("docker/login-action", image)   # pulled the way a stranger pulls it
        binaries = self._job("release-binaries")
        self.assertIn('for f in "$FILE" SHA256SUMS; do', binaries)
        self.assertIn('"https://github.com/${REPO}/releases/download/${TAG}/${f}"', binaries)
        built = re.findall(r"name: ([\w-]+), exe", (self.WORKFLOWS / "binaries.yml").read_text(encoding="utf-8"))
        self.assertEqual(sorted(re.findall(r"name: ([\w-]+), exe", binaries)), sorted(built))
        for name, job in (("pip-from-the-tag", pip), ("image", image), ("release-binaries", binaries)):
            self.assertIn("tools/killer_demo.py", job, name)
            self.assertIn('= "aiterprise-scan $V"', job, f"{name} does not check the version it got")
        action = self._job("action")
        self.assertIn("ref: v${{ needs.version.outputs.version }}", action)
        self.assertEqual(re.findall(r"uses: (\./\S+)", action), ["./published/action", "./published/action"])
        self.assertIn('test "$KD" = "1"', action)
        self.assertIn('test "$CLEAN" = "0"', action)
        hook = self._job("pre-commit")
        self.assertEqual(re.findall(r"pre-commit try-repo .*", hook),
                         ['pre-commit try-repo "https://github.com/${REPO}" aiterprise-scan --ref "v${V}" --all-files)'] * 2)
        self.assertIn('test "$bad" = "1"', hook)
        self.assertIn('test "$good" = "0"', hook)

    def test_the_release_files_are_checked_before_a_binary_is_trusted(self):
        files = self._job("release-files")
        order = [files.index(s) for s in (
            "gh release download",
            "sha256sum -c SHA256SUMS",
            '--certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"',
            "--certificate-oidc-issuer https://token.actions.githubusercontent.com")]
        self.assertEqual(order, sorted(order))
        self.assertIn("needs: [version, release-files]", self._job("release-binaries"))
        self.assertIn("matches SHA256SUMS", self._job("release-binaries"))

    def test_pypi_is_checked_only_when_the_project_publishes_there_and_then_strictly(self):
        job = self._job("pypi")
        self.assertIn(PYPI_SWITCH, job)
        self.assertNotIn("::warning", job)   # switched on, a version missing from PyPI is a failure
        self.assertIn('--index-url https://pypi.org/simple "aiterprise-scan==$V"', job)
        self.assertIn("os: [ubuntu-latest, macos-latest, windows-latest]", job)
        self.assertIn('python-version: "3.11"', job)
        self.assertIn('= "aiterprise-scan $V"', job)
        self.assertIn("tools/killer_demo.py", job)

    def test_the_gitlab_template_is_run_as_shipped_with_its_own_install(self):
        job = self._job("gitlab-template")
        self.assertIn("container: python:3.12-slim", job)
        self.assertNotRegex(job, r"(?m)^\s+AIBOM_INSTALL:")   # the template's own, not one set here
        self.assertIn('job["variables"]["AIBOM_INSTALL"]', job)
        self.assertIn("templates/gitlab/aiterprise-scan.gitlab-ci.yml", job)
        self.assertIn('test "$bad" = "1"', job)
        self.assertIn('test "$good" = "0"', job)

    def test_no_expression_is_spliced_into_a_script(self):
        # values reach shell code through env only; a `${{ }}` inside `run:` is pasted into the script
        in_run, indent, scripts = False, 0, 0
        for line in self.WORKFLOW.read_text(encoding="utf-8").splitlines():
            if in_run and line.strip() and len(line) - len(line.lstrip()) <= indent:
                in_run = False
            if in_run or re.match(r"\s*(- )?run: ", line):
                self.assertNotIn("${{", line)
            block = re.match(r"(\s*)(?:- )?run: \|", line)
            if block:
                in_run, indent, scripts = True, len(block.group(1)), scripts + 1
        self.assertGreaterEqual(scripts, 7)


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


class GitHubReleaseTests(unittest.TestCase):
    """The signed files reach a GitHub Release even when an upload to PyPI fails."""

    WORKFLOWS = ROOT / ".github" / "workflows"

    def _job(self, workflow, job):
        text = (self.WORKFLOWS / workflow).read_text(encoding="utf-8")
        return re.search(rf"^  {job}:\n(.*?)(?=^  \S|\Z)", text, re.MULTILINE | re.DOTALL).group(1)

    def test_the_github_release_does_not_wait_for_pypi(self):
        needs = re.search(r"^    needs:\s*\[([^\]]*)\]", self._job("release.yml", "github-release"), re.MULTILINE)
        names = {n.strip() for n in needs.group(1).split(",")}
        self.assertIn("sign", names)
        self.assertNotIn("pypi", names)

    def test_a_release_run_can_be_published_later_and_only_after_its_signatures_check_out(self):
        text = (self.WORKFLOWS / "publish-release.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(text, r"(?m)^  (push|pull_request|schedule):")
        job = self._job("publish-release.yml", "publish")
        order = [job.index(s) for s in (
            "actions/download-artifact",
            "sha256sum -c SHA256SUMS",
            "--certificate-identity \"https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}\"",
            "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
            "softprops/action-gh-release")]
        self.assertEqual(order, sorted(order), "the release step must come after the checks")
        # inputs reach shell code through the environment only, never spliced into a script
        for line in job.splitlines():
            if "${{ inputs." in line:
                self.assertRegex(line.strip(), r"^[A-Z_]+: \$\{\{ inputs\.[a-z-]+ \}\}$|^(tag_name|run-id): ", line)

    def test_the_tag_and_run_are_checked_before_anything_is_read(self):
        job = self._job("publish-release.yml", "publish")
        self.assertIn('[[ "$TAG" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]', job)
        self.assertIn('[[ "$RUN" =~ ^[0-9]+$ ]]', job)
        self.assertLess(job.index('[[ "$RUN" =~'), job.index("actions/download-artifact"))
        # the run must be one of release.yml, started by the push of this very tag
        cond = re.search(r'^\s*if (.*); then\n\s*echo "run \$RUN is not the release run of \$TAG"\n\s*exit 1', job,
                         re.MULTILINE)
        self.assertIsNotNone(cond, "the run check is gone")
        for clause in ('[ "$path" != ".github/workflows/release.yml" ]', '[ "$branch" != "$TAG" ]',
                       '[ "$event" != "push" ]'):
            self.assertIn(clause, cond.group(1).split(" || "))
        self.assertLess(cond.start(), job.index("actions/download-artifact"))


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
