"""Command rules and poison patterns (design doc 13 C26 / C30 / C31).

The shipped rule sets that judge text found in MCP configs, MCP bundles, agent skills and package
archives, and the findings they make. Command rules (`command-rules.json`) judge a command line;
poison patterns (`poison-patterns.json`) judge free text an agent reads, such as a tool description
or a skill's instructions. Static only: nothing is run.

A rule hit by the same text makes the same finding wherever the text was found. What the caller
decides is only the rule family (`ait.mcp`, `ait.skill`, `ait.archive`), the component, the place,
the wording of the title and how two occurrences in one file are told apart (the discriminator,
which is part of the finding's fingerprint).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from functools import lru_cache
from typing import Any

from . import data, secrets
from .model import (
    OWASP_PROMPT_INJECTION,
    OWASP_SENSITIVE_INFO,
    OWASP_SUPPLY_CHAIN,
    Component,
    Evidence,
    Finding,
    Location,
)

FAMILIES = ("ait.mcp", "ait.skill", "ait.archive")

_VERDICT = {  # severity -> (verdict, confidence)
    "critical": ("malicious", 90),
    "high": ("suspicious", 75),
    "medium": ("suspicious", 55),
    "low": ("suspicious", 40),
    "info": ("benign", 30),
}
_SENSITIVE = ("cred", "exfil", "exec", "download-exec")  # command categories that also disclose data
_MAX_POISON_MATCH = 160

Rules = tuple[tuple[dict[str, Any], "re.Pattern[str]"], ...]


@lru_cache(maxsize=1)
def _command_rules() -> Rules:
    # compiled beside the rule, never into it: data.load() is shared by the whole process
    return tuple((rule, re.compile(rule["pattern"], re.IGNORECASE))
                 for rule in data.load("command-rules.json")["rules"])


@lru_cache(maxsize=1)
def _poison_rules() -> Rules:
    # poison patterns carry their own (?i)
    return tuple((rule, re.compile(rule["pattern"])) for rule in data.load("poison-patterns.json")["rules"])


def _matches(text: str, rules: Rules) -> Iterator[tuple[dict[str, Any], re.Match[str]]]:
    if not text:
        return
    for rule, pattern in rules:
        m = pattern.search(text)
        if m:
            yield rule, m


def _check_family(family: str) -> None:
    if family not in FAMILIES:
        raise ValueError(f"unknown rule family {family!r}: one of {', '.join(FAMILIES)}")


def command_findings(text: str, family: str, component: Component | None, location: Location, *,
                     title: str | None = None, discriminator: Callable[[str], str] | None = None,
                     detail: dict[str, Any] | None = None) -> list[Finding]:
    """One finding per command rule that fires on the command line `text`.

    `title` is what comes before ": <rule description>" (default "Dangerous command in <component>",
    so a caller without a component gives one);
    `discriminator` turns a rule id into the finding's discriminator (default: the rule id);
    `detail` is added to the evidence detail."""
    _check_family(family)
    findings: list[Finding] = []
    for rule, m in _matches(text, _command_rules()):
        verdict, confidence = _VERDICT[rule["severity"]]
        findings.append(Finding(
            rule_id=f"{family}.cmd.{rule['id']}",
            title=f"{title or f'Dangerous command in {component.name}'}: {rule['description']}",
            severity=rule["severity"],
            verdict=verdict,
            confidence=confidence,
            component=component,
            location=location,
            evidence=[Evidence(source="ait-rules", record=rule["id"],
                               detail={"category": rule["category"],
                                       "match": secrets.redact_secrets_in(m.group(0)), **(detail or {})})],
            remediation=rule["remediation"],
            maps_to=([OWASP_SENSITIVE_INFO, OWASP_SUPPLY_CHAIN] if rule["category"] in _SENSITIVE
                     else [OWASP_SUPPLY_CHAIN]),
            discriminator=discriminator(rule["id"]) if discriminator else rule["id"],
        ))
    return findings


def command_findings_by_line(text: str, family: str, component: Component | None, path: str) -> list[Finding]:
    """Command rules on every non-blank line of a script at `path`. Each finding points at its line,
    and its discriminator is "<rule id>:<path>:<line>"."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip():
            findings += command_findings(line, family, component, Location(path, lineno),
                                         discriminator=lambda rule, n=lineno: f"{rule}:{path}:{n}")
    return findings


def poison_findings(text: str, family: str, component: Component, location: Location,
                    field: str) -> list[Finding]:
    """One finding per poison pattern that fires on `text`, the free text an agent reads in `field`
    (for example "description" or "body"). Its discriminator is "<rule id>:<field>". Hidden
    (steganographic) text is never echoed: the match shows the rule id instead."""
    _check_family(family)
    findings: list[Finding] = []
    for rule, m in _matches(text, _poison_rules()):
        verdict, confidence = _VERDICT[rule["severity"]]
        match = (f"<{rule['id']}>" if rule["category"] == "steganography"
                 else secrets.redact_secrets_in(m.group(0))[:_MAX_POISON_MATCH])
        findings.append(Finding(
            rule_id=f"{family}.desc.{rule['id']}",
            title=f"Prompt poisoning in {component.name} ({field}): {rule['description']}",
            severity=rule["severity"],
            verdict=verdict,
            confidence=confidence,
            component=component,
            location=location,
            evidence=[Evidence(source="ait-rules", record=rule["id"],
                               detail={"category": rule["category"], "field": field, "match": match})],
            remediation=rule["remediation"],
            maps_to=[OWASP_PROMPT_INJECTION, OWASP_SUPPLY_CHAIN],
            discriminator=f"{rule['id']}:{field}",
        ))
    return findings
