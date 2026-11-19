"""The issue forms and the pull-request template: what a reporter is asked for, and where they are sent."""

import re
import unittest
from pathlib import Path

from aiterprise_scan import miniyaml

ROOT = Path(__file__).resolve().parents[1]
FORMS = ROOT / ".github" / "ISSUE_TEMPLATE"
ADVISORY = "https://github.com/jtopaz1/aiterprise-aibom/security/advisories/new"
# GitHub's issue-forms syntax: the element types a form body may hold
TYPES = {"markdown", "textarea", "input", "dropdown", "checkboxes"}


def _forms():
    return {p.name: miniyaml.load(p.read_text(encoding="utf-8")) for p in sorted(FORMS.glob("*.yml"))
            if p.name != "config.yml"}


def _fields(form):
    return {el["id"]: el for el in form["body"] if el["type"] != "markdown"}


def _required(el):
    return (el.get("validations") or {}).get("required") is True


class IssueFormTests(unittest.TestCase):
    def test_the_forms_are_the_three_kinds_of_report_and_a_contact_request(self):
        self.assertEqual(sorted(_forms()), ["bug.yml", "false-positive.yml", "feature.yml",
                                            "security-contact.yml"])

    def test_a_reporter_without_private_reporting_can_ask_for_a_contact_and_say_nothing(self):
        # Private vulnerability reporting is the owner's switch; until it is on, this is the way in.
        form = _forms()["security-contact.yml"]
        self.assertEqual(form.get("title"), "Security contact request")
        # nothing to type the problem into: a notice and one box to tick
        self.assertEqual(sorted({el["type"] for el in form["body"]}), ["checkboxes", "markdown"])
        options = _fields(form)["no-details"]["attributes"]["options"]
        self.assertTrue(options and all(o.get("required") is True for o in options))
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn(f'"{form["name"]}"', security)

    def test_each_form_is_one_github_reads(self):
        for name, form in _forms().items():
            with self.subTest(name):
                self.assertTrue(form.get("name") and form.get("description"))
                self.assertTrue(form.get("labels"))
                ids = []
                for el in form["body"]:
                    self.assertIn(el["type"], TYPES)
                    if el["type"] == "markdown":
                        self.assertTrue(el["attributes"]["value"].strip())
                        continue
                    self.assertTrue(el["attributes"]["label"].strip())
                    ids.append(el["id"])
                    if el["type"] in ("dropdown", "checkboxes"):
                        self.assertTrue(el["attributes"]["options"])
                self.assertEqual(len(ids), len(set(ids)), "ids must be unique")
                self.assertEqual([i for i in ids if not re.fullmatch(r"[a-z][a-z0-9-]*", i)], [])

    def test_a_bug_or_false_positive_report_says_which_build_and_how_it_was_installed(self):
        for name in ("bug.yml", "false-positive.yml"):
            with self.subTest(name):
                fields = _fields(_forms()[name])
                self.assertTrue(_required(fields["version"]))
                self.assertIn("aiterprise-scan version", fields["version"]["attributes"]["description"])
                self.assertTrue(_required(fields["install"]))
                options = " | ".join(fields["install"]["attributes"]["options"])
                # every channel the docs offer (PublishedChannelsTests), and a checkout
                for channel in ("git tag", "binary", "image", "GitHub Action", "pre-commit", "checkout"):
                    self.assertIn(channel, options)

    def test_a_false_positive_names_the_rule_the_finding_and_the_smallest_input(self):
        fields = _fields(_forms()["false-positive.yml"])
        for needed in ("rule", "finding", "input", "why", "version", "install"):
            self.assertTrue(_required(fields[needed]), needed)
        rule = fields["rule"]["attributes"]["placeholder"]
        rules_doc = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
        self.assertIn(f"`{rule}`", rules_doc, "the example rule id is not one the scanner reports")
        self.assertIn("report-fp", (FORMS / "false-positive.yml").read_text(encoding="utf-8"))

    def test_vulnerabilities_and_evasions_are_sent_to_a_private_advisory_not_a_public_issue(self):
        config = miniyaml.load((FORMS / "config.yml").read_text(encoding="utf-8"))
        self.assertIs(config["blank_issues_enabled"], False)
        self.assertIn(ADVISORY, [link["url"] for link in config["contact_links"]])
        self.assertIn("Report a vulnerability", (ROOT / "SECURITY.md").read_text(encoding="utf-8"))
        for name in _forms():
            with self.subTest(name):
                text = (FORMS / name).read_text(encoding="utf-8")
                self.assertIn(ADVISORY, text)
                self.assertRegex(text, r"(?i)evasion")


class PullRequestTemplateTests(unittest.TestCase):
    def test_the_checklist_is_what_contributing_asks_for(self):
        text = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        commands = re.findall(r"`((?:PYTHONPATH=src )?python [^`]+)`", text)
        self.assertGreaterEqual(len(commands), 3, commands)
        self.assertEqual([c for c in commands if c not in contributing], [])
        for asked in ("Signed-off-by", "docs/STATUS.md", "tools/gen_rules_doc.py"):
            self.assertIn(asked, text)
            self.assertIn(asked, contributing)
        self.assertGreaterEqual(len(re.findall(r"(?m)^- \[ \] ", text)), 4)


if __name__ == "__main__":
    unittest.main()
