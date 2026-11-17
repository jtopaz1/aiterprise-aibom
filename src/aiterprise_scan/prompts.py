"""Prompts as components (design doc 13 §4.2, C02): the text AI agents and applications follow.

- agent instruction files, read by coding agents with every request: `AGENTS.md`, `CLAUDE.md`,
  `GEMINI.md`, `.github/copilot-instructions.md`, `.cursorrules` and the rule folders of Cursor,
  Windsurf, Cline, Roo Code, Kiro, Amazon Q and Continue;
- sub-agents (with the tools they are granted) and commands: `.claude/agents/`, `.github/agents/`,
  `.github/chatmodes/`, `.github/prompts/*.prompt.md`, `.gemini/commands/`, `.cursor/commands/`.
  Claude Code's `.claude/commands/` are agent skills (`skills.py`) and are not listed twice;
- prompt templates: `*.prompty`, `*.prompt.yml` (GitHub Models), `*.prompt`;
- prompts pulled from a hub in code: LangChain `hub.pull("owner/name")`, LangSmith `pull_prompt(...)`.

Which files are prompts is data (`data/ait/ai-assets.json`). This is inventory: the design leaves
content rules on prompts to v2, and the secrets pass reads these files like any other. A prompt's
text is never copied into the component, only its path, kind, reader and tool grants.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import data
from .callargs import line_at
from .model import Component, Location, merge_components
from .skills import as_list, front_matter
from .textio import TooLarge, read_text
from .walk import is_test_path, rel_posix

MAX_BYTES = 2 * 1024 * 1024
_CODE_SUFFIXES = {".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
_HUB_ID = re.compile(r"^[\w.-]+(?:/[\w.-]+)?(?::[\w.-]+)?$")


@lru_cache(maxsize=1)
def _spec() -> dict[str, Any]:
    return data.load("ai-assets.json")["prompts"]


@lru_cache(maxsize=1)
def _hub_re() -> re.Pattern[str]:
    calls = "|".join(r"\b" + re.escape(c) for c in _spec()["hub_calls"])
    return re.compile(r"(?:" + calls + r")\s*\(\s*(['\"])([^'\"\s]+)\1")


def prompt_file(rel: str) -> dict[str, Any] | None:
    """What a file at this root-relative posix path is to an agent, or None if it is not a prompt."""
    spec = _spec()
    name = rel.rsplit("/", 1)[-1]
    padded = "/" + rel
    if name in spec["names"]:
        kind, reader = spec["names"][name]
        return {"kind": kind, "read_by": reader}
    for path, (kind, reader) in spec["paths"].items():
        if padded.endswith("/" + path):
            return {"kind": kind, "read_by": reader}
    for entry in spec["dirs"]:
        if "/" + entry["dir"] + "/" in padded and name.endswith(tuple(entry["suffixes"])):
            return {k: v for k, v in entry.items() if k in ("kind", "read_by", "omitted_tools")}
    for suffix, kind, reader in spec["suffixes"]:
        if name.endswith(suffix) and name != suffix:
            return {"kind": kind, "read_by": reader}
    return None


def _file_component(path: Path, rel: str, what: dict[str, Any]) -> Component:
    props: dict[str, Any] = {"kind": what["kind"], "path": rel}
    if what.get("read_by"):
        props["read_by"] = what["read_by"]
    if what["kind"] in ("sub-agent", "command") and rel.endswith(".md"):
        try:
            meta, _ = front_matter(read_text(path, max_bytes=MAX_BYTES))
        except (OSError, TooLarge):
            meta = {}
        tools = as_list(meta.get("tools"))
        if tools:
            props["tools"] = tools
        elif what.get("omitted_tools") == "all":
            props["all_tools"] = True  # e.g. a Claude Code sub-agent without `tools:` inherits every tool
    return Component(name=rel, ctype="prompt", source="file", locations=[Location(rel)], properties=props)


def _hub_refs(text: str, rel: str) -> list[Component]:
    out: list[Component] = []
    for m in _hub_re().finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        if text[line_start:m.start()].lstrip().startswith(("#", "//")) or text[m.start() - 1:m.start()] == "`":
            continue  # a comment, or an example quoted in a docstring
        ref = m.group(2)
        if not _HUB_ID.match(ref):
            continue
        out.append(Component(name=ref, ctype="prompt", source="code-ref",
                             locations=[Location(rel, line_at(text, m.start(2)))],
                             properties={"kind": "hub"}))
    return out


def discover_prompts(root: Path, files: list[Path]) -> list[Component]:
    root = Path(root)
    found: list[Component] = []
    for f in files:
        path = f if f.is_absolute() else root / f
        rel = rel_posix(path, root)
        what = prompt_file(rel)
        if what is not None:
            found.append(_file_component(path, rel, what))
        elif path.suffix.lower() in _CODE_SUFFIXES and not is_test_path(rel):
            try:
                text = read_text(path, max_bytes=MAX_BYTES)
            except (OSError, TooLarge):
                continue
            if "pull" in text:
                found += _hub_refs(text, rel)
    return merge_components(found)
