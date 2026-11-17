"""Agent-skill / plugin analyzer (design doc 13 C30 / C31).

Detects skill trees (``SKILL.md``), Claude Code plugins
(``.claude-plugin/plugin.json``) and slash-command files (``.claude/commands/*.md``),
then judges them statically: instruction poisoning on the markdown body, dangerous
commands in bundled scripts and plugin hooks, and a SkillSpector-style 0-100 risk
score with an explicit recommendation (design doc G3). Nothing is executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import miniyaml, sources, textrules
from .model import SEVERITY_RANK, Component, Finding, Location, not_analysable
from .textio import TooLarge, loads_jsonc, read_text
from .walk import walk, rel_posix

SCRIPT_EXTS = {".sh", ".bash", ".ps1", ".py", ".js", ".ts", ".bat", ".cmd"}
_RISK_WEIGHT = {"critical": 45, "high": 20, "medium": 8, "low": 3, "info": 1}
_MAX_SCRIPT_BYTES = 512 * 1024


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def find_skill_dirs(root: Path, files: list[Path]) -> list[Path]:
    """Skill/plugin roots and slash-command files found among `files`.

    Returns directories (containing ``SKILL.md`` or ``.claude-plugin/plugin.json``)
    and individual ``.claude/commands/*.md`` files, de-duplicated and sorted.
    """
    out: list[Path] = []
    seen: set[str] = set()

    def _add(p: Path) -> None:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            out.append(p)

    for f in files:
        name = f.name
        parts = [p.lower() for p in f.parts]
        if name == "SKILL.md":
            _add(f.parent)
        elif name == "plugin.json" and f.parent.name == ".claude-plugin":
            _add(f.parent.parent)
        elif (name.lower().endswith(".md") and len(parts) >= 3
              and parts[-2] == "commands" and parts[-3] == ".claude"):
            _add(f)
    out.sort(key=lambda p: str(p).lower())
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _front_matter(text: str) -> tuple[dict[str, Any], str]:
    """Split YAML front matter from a markdown body. Returns ({}, text) if none."""
    t = text.lstrip("﻿")
    lines = t.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return {}, text
    # first line is '---'; find the closing '---'
    body_start = None
    fm_lines: list[str] = []
    for i in range(1, len(lines)):
        if lines[i].rstrip("\r\n") == "---":
            body_start = i + 1
            break
        fm_lines.append(lines[i])
    if body_start is None:
        return {}, text
    try:
        fm = miniyaml.load("".join(fm_lines))
    except Exception:
        fm = {}
    if not isinstance(fm, dict):
        fm = {}
    return fm, "".join(lines[body_start:])


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [p.strip() for p in value.replace(",", " ").split() if p.strip()]
    return [str(value)]


def _risk(findings: list[Finding]) -> tuple[int, str]:
    score = 0
    has_critical = False
    for f in findings:
        score += _RISK_WEIGHT.get(f.severity, 0)
        if f.severity == "critical":
            has_critical = True
    score = min(score, 100)
    if has_critical:
        rec = "DO NOT INSTALL"
    elif score >= 50:
        rec = "REVIEW BEFORE INSTALL"
    elif any(f.rule_id.endswith(".not-analysable") for f in findings):
        rec = "NOT FULLY CHECKED"  # a skipped file is unknown, never "safe" (design doc 13 §4.8)
    elif score >= 20:
        rec = "REVIEW RECOMMENDED"
    else:
        rec = "LIKELY SAFE"
    return score, rec


def _scan_scripts(skill_dir: Path, root: Path, comp: Component) -> list[Finding]:
    findings: list[Finding] = []
    try:
        members = walk(skill_dir, all_files=True)
    except OSError:
        return findings
    for script in members:
        if script.suffix.lower() not in SCRIPT_EXTS:
            continue
        rel = rel_posix(script, root)
        try:
            text = read_text(script, max_bytes=_MAX_SCRIPT_BYTES)
        except (OSError, TooLarge) as err:
            reason = (f"larger than {_MAX_SCRIPT_BYTES // 1024} KiB" if isinstance(err, TooLarge)
                      else f"unreadable: {type(err).__name__}")
            findings.append(not_analysable("skill", rel, f"Bundled script {script.name}", reason, comp))
            continue
        findings += textrules.command_findings_by_line(text, "ait.skill", comp, rel)
    return findings


# ---------------------------------------------------------------------------
# Per-unit analysis
# ---------------------------------------------------------------------------


def _analyze_skill_dir(skill_dir: Path, root: Path) -> tuple[Component, list[Finding]]:
    skill_md = skill_dir / "SKILL.md"
    rel = rel_posix(skill_md, root)
    unread = None
    try:
        text = read_text(skill_md)
    except (OSError, TooLarge) as err:
        text, unread = "", f"{type(err).__name__}"
    fm, body = _front_matter(text)
    name = str(fm.get("name") or skill_dir.name)
    comp = Component(
        name=name, ctype="agent-skill", source="config",
        locations=[Location(rel, 1)],
        properties={
            "kind": "skill",
            "description": fm.get("description"),
            "allowed-tools": _as_list(fm.get("allowed-tools") or fm.get("allowed_tools")),
            "path": rel_posix(skill_dir, root),
        },
    )
    findings = textrules.poison_findings(body, "ait.skill", comp, Location(rel, 1), "body")
    if unread:
        findings.append(not_analysable("skill", rel, "SKILL.md", f"unreadable: {unread}", comp))
    if isinstance(fm.get("description"), str):
        findings += textrules.poison_findings(fm["description"], "ait.skill", comp, Location(rel, 1), "description")
    findings += _scan_scripts(skill_dir, root, comp)
    return _finalize(comp, findings)


def _analyze_plugin_dir(plugin_dir: Path, root: Path) -> tuple[Component, list[Finding]]:
    manifest = plugin_dir / ".claude-plugin" / "plugin.json"
    rel = rel_posix(manifest, root)
    meta: dict[str, Any] = {}
    try:
        parsed = loads_jsonc(read_text(manifest))
        if isinstance(parsed, dict):
            meta = parsed
    except (OSError, TooLarge, ValueError):
        pass
    name = str(meta.get("name") or plugin_dir.name)
    comp = Component(
        name=name, ctype="agent-skill", source="config",
        locations=[Location(rel, 1)],
        properties={
            "kind": "plugin",
            "description": meta.get("description"),
            "path": rel_posix(plugin_dir, root),
        },
    )
    findings: list[Finding] = []
    if isinstance(meta.get("description"), str):
        findings += textrules.poison_findings(meta["description"], "ait.skill", comp, Location(rel, 1), "description")
    # plugin.json hooks run shell commands
    for cmd in _plugin_hook_commands(meta):
        findings += textrules.command_findings(cmd, "ait.skill", comp, Location(rel, 1))
    findings += _scan_scripts(plugin_dir, root, comp)
    return _finalize(comp, findings)


def _plugin_hook_commands(meta: dict) -> list[str]:
    cmds: list[str] = []

    def _collect(node: Any) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("command"), str):
                cmds.append(node["command"])
            for v in node.values():
                _collect(v)
        elif isinstance(node, list):
            for v in node:
                _collect(v)

    _collect(meta.get("hooks"))
    return cmds


def _analyze_command_file(md: Path, root: Path) -> tuple[Component, list[Finding]]:
    rel = rel_posix(md, root)
    try:
        text = read_text(md)
    except (OSError, TooLarge):
        text = ""
    fm, body = _front_matter(text)
    name = str(fm.get("name") or md.stem)
    comp = Component(
        name=name, ctype="agent-skill", source="config",
        locations=[Location(rel, 1)],
        properties={
            "kind": "command",
            "description": fm.get("description"),
            "allowed-tools": _as_list(fm.get("allowed-tools") or fm.get("allowed_tools")),
            "path": rel,
        },
    )
    findings = textrules.poison_findings(body, "ait.skill", comp, Location(rel, 1), "body")
    # command/prompt files may embed shell via `!`...`` or fenced blocks
    findings += textrules.command_findings_by_line(body, "ait.skill", comp, rel)
    return _finalize(comp, findings)


def _finalize(comp: Component, findings: list[Finding]) -> tuple[Component, list[Finding]]:
    score, rec = _risk(findings)
    comp.properties["risk_score"] = score
    comp.properties["recommendation"] = rec
    comp.properties["finding_count"] = len(findings)
    worst = None
    for f in findings:
        if worst is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]:
            worst = f.severity
    if worst:
        comp.properties["max_severity"] = worst
    return comp, findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def analyze_skills(root: Path, files: list[Path], result=None) -> tuple[list[Component], list[Finding]]:
    """Every skill, plugin and command file under `root`. Given a `result`, records the coverage."""
    components: list[Component] = []
    findings: list[Finding] = []
    for unit in find_skill_dirs(root, files):
        if unit.is_dir():
            if (unit / "SKILL.md").is_file():
                comp, fs = _analyze_skill_dir(unit, root)
            elif (unit / ".claude-plugin" / "plugin.json").is_file():
                comp, fs = _analyze_plugin_dir(unit, root)
            else:
                continue
        elif unit.is_file():
            comp, fs = _analyze_command_file(unit, root)
        else:
            continue
        components.append(comp)
        findings.extend(fs)
    sources.count(result, sources.SKILLS, (c for c in components if c.ctype == "agent-skill"), findings)
    return components, findings
