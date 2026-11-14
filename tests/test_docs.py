"""The docs site stays in step with the code: the rules reference is generated, and every page is in the nav."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


class RulesReferenceTests(unittest.TestCase):
    def test_rules_reference_is_up_to_date(self):
        import gen_rules_doc

        expected = gen_rules_doc.render()
        actual = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
        self.assertEqual(actual, expected, "docs/rules.md is stale: run python tools/gen_rules_doc.py")

    def test_every_data_rule_is_listed(self):
        import json

        text = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
        data = ROOT / "src" / "aiterprise_scan" / "data" / "ait"
        for name in ("command-rules.json", "poison-patterns.json"):
            for rule in json.loads((data / name).read_text(encoding="utf-8"))["rules"]:
                self.assertIn(f"`{rule['id']}`", text)
        for rid in json.loads((data / "model-rules.json").read_text(encoding="utf-8"))["rules"]:
            self.assertIn(f"`{rid}`", text)

    def test_measured_rates_are_shown_and_unmeasured_say_so(self):
        text = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
        self.assertRegex(text, r"`ait\.secret\.private-key`[^\n]*3\.41 %")
        self.assertIn("not measured", text)


class NavTests(unittest.TestCase):
    def test_every_page_is_in_the_nav_and_exists(self):
        nav = re.findall(r":\s*([\w./-]+\.md)\s*$", (ROOT / "mkdocs.yml").read_text(encoding="utf-8"), re.M)
        pages = sorted(p.relative_to(ROOT / "docs").as_posix() for p in (ROOT / "docs").rglob("*.md"))
        self.assertEqual(sorted(nav), pages)


if __name__ == "__main__":
    unittest.main()
