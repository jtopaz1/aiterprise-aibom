"""tools/measure_fp.py: project lists from a file, and merging one corpus's families into the quality file."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import measure_fp  # noqa: E402

SECRETS = {"corpus": "site-packages", "evaluated_at": "2026-11-14", "samples": 205, "fp_rate_measured": 0.0341,
           "flagged": 7, "scope": "family"}
OLD = {"version": "2026.11.14", "method": "old method", "rules": {
    "ait.secret.*": SECRETS,
    "ait.secret.private-key": {**SECRETS, "scope": "rule"},
    "ait.skill.*": {"corpus": "old skills", "evaluated_at": "2026-11-01", "samples": 30, "fp_rate_measured": 0.5,
                    "flagged": 15, "scope": "family"},
    "ait.skill.gone": {"corpus": "old skills", "evaluated_at": "2026-11-01", "samples": 30,
                       "fp_rate_measured": 0.5, "flagged": 15, "scope": "rule"},
}}
NEW = {"version": "2026.11.16", "method": "new method", "rules": {
    "ait.skill.*": {"corpus": "new skills", "evaluated_at": "2026-11-16", "samples": 100, "fp_rate_measured": 0.02,
                    "flagged": 2, "scope": "family"},
    "ait.skill.exfil": {"corpus": "new skills", "evaluated_at": "2026-11-16", "samples": 100,
                        "fp_rate_measured": 0.02, "flagged": 2, "scope": "rule"},
}}
CLEAN_SKILL = "---\nname: tidy\ndescription: Formats a table.\n---\n\nSort the rows.\n"


class ProjectListTest(unittest.TestCase):
    def test_a_list_file_gives_one_project_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp, "a"), Path(tmp, "b")
            a.mkdir()
            b.mkdir()
            listing = Path(tmp, "projects.txt")
            listing.write_text(f"# clean skills\n{a}\n\n  {b}  \n", encoding="utf-8")
            self.assertEqual(measure_fp.read_project_list(listing), [a, b])

    def test_a_listed_project_that_does_not_exist_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            listing = Path(tmp, "projects.txt")
            listing.write_text(str(Path(tmp, "missing")) + "\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as caught:
                measure_fp.read_project_list(listing)
            self.assertIn("missing", str(caught.exception))


class MergeTest(unittest.TestCase):
    def test_families_not_measured_in_this_run_are_kept(self):
        merged = measure_fp.merge_quality(OLD, NEW, measured=["ait.skill."])
        self.assertEqual(merged["rules"]["ait.secret.*"], SECRETS)
        self.assertIn("ait.secret.private-key", merged["rules"])

    def test_a_measured_family_replaces_all_of_its_old_entries(self):
        merged = measure_fp.merge_quality(OLD, NEW, measured=["ait.skill."])
        self.assertEqual(merged["rules"]["ait.skill.*"]["samples"], 100)
        self.assertIn("ait.skill.exfil", merged["rules"])
        self.assertNotIn("ait.skill.gone", merged["rules"])  # it did not fire on the new corpus

    def test_the_merged_file_carries_the_new_version_and_sorted_rules(self):
        merged = measure_fp.merge_quality(OLD, NEW, measured=["ait.skill."])
        self.assertEqual((merged["version"], merged["method"]), ("2026.11.16", "new method"))
        self.assertEqual(list(merged["rules"]), sorted(merged["rules"]))


class MainTest(unittest.TestCase):
    def run_on_one_clean_skill(self, tmp: str, *extra: str) -> dict:
        skill = Path(tmp, "clean-skill")
        skill.mkdir()
        (skill / "SKILL.md").write_text(CLEAN_SKILL, encoding="utf-8")
        listing = Path(tmp, "projects.txt")
        listing.write_text(f"{skill}\n", encoding="utf-8")
        out = Path(tmp, "rule-quality.json")
        out.write_text(json.dumps(OLD), encoding="utf-8")
        code = measure_fp.main(["--projects-from", str(listing), "--corpus-name", "one clean skill", "--merge",
                                "--write", "--out", str(out), *extra])
        self.assertEqual(code, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_merge_replaces_only_the_requested_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = self.run_on_one_clean_skill(tmp, "--family", "ait.skill.", "--min-samples", "1")
        self.assertEqual(written["rules"]["ait.skill.*"]["fp_rate_measured"], 0.0)
        self.assertEqual(written["rules"]["ait.skill.*"]["samples"], 1)
        self.assertNotIn("ait.skill.gone", written["rules"])
        # the skill's text also gave the secret rules a chance, but that family was not requested
        self.assertEqual(written["rules"]["ait.secret.*"], SECRETS)
        self.assertIn("ait.secret.private-key", written["rules"])

    def test_merge_keeps_the_old_entry_of_a_family_with_too_few_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = self.run_on_one_clean_skill(tmp, "--family", "ait.skill.", "--min-samples", "5")
        self.assertEqual(written["rules"]["ait.skill.*"]["samples"], 30)
        self.assertIn("ait.skill.gone", written["rules"])

    def test_an_unknown_family_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(SystemExit):
            self.run_on_one_clean_skill(tmp, "--family", "ait.nonsense.")


if __name__ == "__main__":
    unittest.main()
