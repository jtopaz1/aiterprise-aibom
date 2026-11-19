"""CHANGELOG.md has a section for every release, and that section is the GitHub release's notes."""

import importlib.util
import io
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("release_notes", ROOT / "tools" / "release_notes.py")
release_notes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_notes)

SAMPLE = """# Changelog

Intro.

## 0.2.0 — 2027-01-10

New things.

### Fixed

- a bug

## 0.1.0 — 2026-11-18

The first release.
"""


class SectionTests(unittest.TestCase):
    def test_the_section_of_a_version_runs_to_the_next_release(self):
        self.assertEqual(release_notes.section(SAMPLE, "0.2.0"), "New things.\n\n### Fixed\n\n- a bug\n")
        self.assertEqual(release_notes.section(SAMPLE, "0.1.0"), "The first release.\n")

    def test_a_version_without_a_section_is_an_error(self):
        with self.assertRaises(LookupError):
            release_notes.section(SAMPLE, "0.3.0")
        with self.assertRaises(LookupError):
            release_notes.section(SAMPLE, "0.1")   # no prefix match: 0.1 is not 0.1.0

    def test_an_empty_section_is_an_error(self):
        with self.assertRaises(LookupError):
            release_notes.section("## 0.1.0 — 2026-11-18\n\n## 0.0.1 — 2026-01-01\n\nx\n", "0.1.0")

    def test_main_takes_a_tag_or_a_version_and_exits_1_without_a_section(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(release_notes.main(["v0.1.0"]), 0)
        self.assertEqual(out.getvalue(), release_notes.section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
                                                                "0.1.0"))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(release_notes.main(["v9.9.9"]), 1)


class ChangelogTests(unittest.TestCase):
    def test_the_version_being_released_has_a_dated_section(self):
        from aiterprise_scan import __version__

        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertRegex(text, rf"(?m)^## {re.escape(__version__)} — \d{{4}}-\d{{2}}-\d{{2}}$")
        self.assertGreater(len(release_notes.section(text, __version__)), 400)

    def test_release_notes_link_absolutely_to_files_that_exist(self):
        # a release page resolves no relative link; a link into the repository names a file on main
        from aiterprise_scan import __version__

        notes = release_notes.section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), __version__)
        targets = re.findall(r"\]\(\s*<?([^)\s>]+)", notes)
        self.assertTrue(targets)
        self.assertEqual([t for t in targets if not t.startswith("https://")], [])
        ours = [m.group(1) for t in targets
                for m in [re.match(r"https://github\.com/jtopaz1/aiterprise-aibom/blob/main/([^#?]+)", t)] if m]
        self.assertTrue(ours)
        self.assertEqual([p for p in ours if not (ROOT / p).exists()], [])

    def test_releases_are_newest_first(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        versions = [tuple(int(p) for p in v.split(".")) for v in re.findall(r"(?m)^## (\d+\.\d+\.\d+) — ", text)]
        self.assertTrue(versions)
        self.assertEqual(versions, sorted(versions, reverse=True))


class ReleaseNotesUsedTests(unittest.TestCase):
    def _job(self, workflow, job):
        text = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
        return re.search(rf"^  {job}:\n(.*?)(?=^  \S|\Z)", text, re.MULTILINE | re.DOTALL).group(1)

    def test_both_ways_of_publishing_a_release_take_its_notes_from_the_changelog(self):
        for workflow, job in (("release.yml", "github-release"), ("publish-release.yml", "publish")):
            with self.subTest(workflow):
                steps = self._job(workflow, job)
                self.assertIn("actions/checkout@v4", steps)
                self.assertRegex(steps, r'python3 (source/)?tools/release_notes\.py "\$TAG" > notes\.md')
                self.assertIn("body_path: notes.md", steps)
                self.assertNotIn("generate_release_notes", steps)
                self.assertLess(steps.index("tools/release_notes.py"), steps.index("softprops/action-gh-release"))


if __name__ == "__main__":
    unittest.main()
