"""Prompts as BOM components (design doc 13 §4.2, C02): agent instruction files, commands, sub-agents,
prompt templates and prompts pulled from a hub."""

import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import prompts
from aiterprise_scan.walk import walk

AGENT = "---\nname: reviewer\ndescription: Reviews diffs.\ntools: Read, Grep\n---\n\nReview the diff.\n"
OPEN_AGENT = "---\nname: fixer\ndescription: Fixes things.\n---\n\nFix it.\n"


def discover(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return {c.name: c for c in prompts.discover_prompts(root, walk(root, all_files=True))}


class PromptFileTests(unittest.TestCase):
    def test_agent_instruction_files_are_prompts_with_their_reader(self):
        found = discover({"AGENTS.md": "Run the tests.", "services/api/AGENTS.md": "Use Go.",
                          "CLAUDE.md": "Be brief.", ".cursorrules": "Use tabs.",
                          ".github/copilot-instructions.md": "Prefer pytest.",
                          ".cursor/rules/style.mdc": "---\nglobs: *.ts\n---\nNo any.",
                          ".github/instructions/py.instructions.md": "Type hints.",
                          # a folder holding several repositories: each one's files count
                          "web/.github/copilot-instructions.md": "x", "web/.cursor/rules/a.mdc": "x"})
        self.assertEqual(sorted(found), [".cursor/rules/style.mdc", ".cursorrules",
                                         ".github/copilot-instructions.md", ".github/instructions/py.instructions.md",
                                         "AGENTS.md", "CLAUDE.md", "services/api/AGENTS.md",
                                         "web/.cursor/rules/a.mdc", "web/.github/copilot-instructions.md"])
        for comp in found.values():
            self.assertEqual((comp.ctype, comp.source, comp.properties["kind"]), ("prompt", "file", "agent-instructions"))
        self.assertEqual(found["CLAUDE.md"].properties["read_by"], "Claude Code")
        self.assertEqual(found[".cursor/rules/style.mdc"].properties["read_by"], "Cursor")
        self.assertEqual(str(found["services/api/AGENTS.md"].locations[0]), "services/api/AGENTS.md")

    def test_sub_agents_record_their_tool_grants(self):
        found = discover({".claude/agents/reviewer.md": AGENT, ".claude/agents/fixer.md": OPEN_AGENT,
                          ".github/chatmodes/plan.chatmode.md": OPEN_AGENT, ".github/prompts/fix.prompt.md": OPEN_AGENT})
        reviewer, fixer = found[".claude/agents/reviewer.md"], found[".claude/agents/fixer.md"]
        self.assertEqual((reviewer.properties["kind"], reviewer.properties["tools"]), ("sub-agent", ["Read", "Grep"]))
        self.assertNotIn("all_tools", reviewer.properties)
        self.assertTrue(fixer.properties["all_tools"])  # no `tools:` list: the sub-agent inherits every tool
        # elsewhere an omitted list means the reader's defaults, not every tool
        self.assertNotIn("all_tools", found[".github/chatmodes/plan.chatmode.md"].properties)
        self.assertNotIn("all_tools", found[".github/prompts/fix.prompt.md"].properties)

    def test_commands_and_templates(self):
        found = discover({".github/prompts/fix.prompt.md": "Fix #file", ".gemini/commands/plan.toml": 'prompt = "x"',
                          "prompts/summarise.prompty": "---\nname: s\n---\nsystem: hi",
                          "eval/grader.prompt.yml": "messages: []", "templates/answer.prompt": "Answer: {q}"})
        kinds = {name: c.properties["kind"] for name, c in found.items()}
        self.assertEqual(kinds, {".github/prompts/fix.prompt.md": "command", ".gemini/commands/plan.toml": "command",
                                 "prompts/summarise.prompty": "template", "eval/grader.prompt.yml": "template",
                                 "templates/answer.prompt": "template"})

    def test_files_that_are_not_prompts(self):
        found = discover({"README.md": "Run the tests.", "docs/AGENTS-guide.md": "x", "notes.prompts.txt": "x",
                          ".claude/commands/deploy.md": "Deploy it.",  # a slash command: the skills analyzer owns it
                          ".claude/settings.json": "{}", ".claude/agents/notes.txt": "x",
                          ".github/instructions/README.md": "x",  # not *.instructions.md
                          ".prompt": "PS1='$ '"})  # a dotfile named like the suffix
        self.assertEqual(found, {})

    def test_the_text_of_a_prompt_is_not_copied_into_the_component(self):
        found = discover({"CLAUDE.md": "The staging password policy is in vault path secret/ops."})
        self.assertNotIn("vault path", repr(found["CLAUDE.md"].to_dict()))


class HubReferenceTests(unittest.TestCase):
    def test_langchain_hub_and_langsmith_prompts(self):
        found = discover({"app.py": 'from langchain import hub\n\nprompt = hub.pull("rlm/rag-prompt")\n'
                                    'other = client.pull_prompt("joke-generator:1a2b3c4d")\n',
                          "agent.ts": 'import * as hub from "langchain/hub";\nconst p = await hub.pull("hwchase17/react");\n'})
        self.assertEqual(sorted(found), ["hwchase17/react", "joke-generator:1a2b3c4d", "rlm/rag-prompt"])
        rag = found["rlm/rag-prompt"]
        self.assertEqual((rag.ctype, rag.source, rag.properties["kind"], str(rag.locations[0])),
                         ("prompt", "code-ref", "hub", "app.py:3"))

    def test_references_that_are_not_static(self):
        found = discover({"app.py": "name = 'x/y'\nprompt = hub.pull(name)\n# hub.pull(\"a/b\")\n"
                                    "odd = hub.pull(\"a/b/c\")\n",
                          "README.md": 'Call `hub.pull("rlm/rag-prompt")`.'})
        self.assertEqual(found, {})

    def test_examples_in_docstrings_and_tests_are_not_uses(self):
        found = discover({"lib.py": '"""Pull a prompt with `hub.pull("owner/name")`."""\n',
                          "tests/test_chain.py": 'p = hub.pull("rlm/rag-prompt")\n'})
        self.assertEqual(found, {})

    def test_prompt_files_in_test_folders_are_still_prompts(self):
        # an agent working in that folder reads it all the same
        self.assertEqual(list(discover({"tests/fixtures/AGENTS.md": "x"})), ["tests/fixtures/AGENTS.md"])


if __name__ == "__main__":
    unittest.main()
