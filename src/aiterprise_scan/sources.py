"""The sources a scan consults, each named once (GLOSSARY.md: source, coverage).

A source is a data set (the malicious-package snapshot, OSV, KEV), a service (a registry, SecDB) or
one of the scanner's own analyzers. Its `name` is the key of its coverage entry in a report
(`examined`). Its `families` are the rule-id prefixes whose findings it can raise; from them a
finding's report says how many sources were consulted for it (`for_rule`).

This module is data and two small functions, so that every source, the scan and `quality` can use
it without importing an analyzer. Third-party providers (`ext.*`) are not listed: each is its own
source under the provider's name (`providers.REGISTRY`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .model import Component, Finding, ScanResult


@dataclass(frozen=True)
class Source:
    name: str
    families: tuple[str, ...] = ()


# The order is the order a family's sources are listed in (and so the order of `skipped`).
AIT_MALICIOUS = Source("ait-malicious", ("ait.pkg.",))
OSV = Source("osv", ("ait.pkg.", "ait.vuln."))
OSV_SUBSET = Source("osv-subset", ("ait.pkg.", "ait.vuln."))
KEV = Source("kev", ("ait.vuln.",))
REGISTRY = Source("registry", ("ait.pkg.",))
MODEL_FILES = Source("model-files", ("ait.model.",))
MCP = Source("mcp", ("ait.mcp.",))
SKILLS = Source("skills", ("ait.skill.",))
LICENCES = Source("licences", ("ait.licence.",))
SECRETS = Source("secrets", ("ait.secret.",))
ARCHIVES = Source("archives", ("ait.pkg.", "ait.model.", "ait.mcp.", "ait.archive."))
SECDB = Source("secdb", ("ait.pkg.", "ait.model.", "ait.mcp."))
POLICY = Source("policy", ("ait.policy.",))
# Steps that list components and raise no rule family of their own. They have a coverage entry
# only when they count something (BOM files) or fail.
BOM_INGEST = Source("bom-ingest")
DISCOVER = Source("discover")
IMPORTS = Source("imports")
MODEL_REFS = Source("model-refs")
PROMPTS = Source("prompts")
AI_SERVICES = Source("ai-services")  # AI endpoints and vector stores
PROVIDERS = Source("providers")  # the step that runs the third-party providers
DEPS_DEV = Source("deps.dev")  # package licences, recorded in the BOM (no verdicts of its own)

ALL: tuple[Source, ...] = (
    AIT_MALICIOUS, OSV, OSV_SUBSET, KEV, REGISTRY, MODEL_FILES, MCP, SKILLS, LICENCES, SECRETS, ARCHIVES, SECDB,
    POLICY, BOM_INGEST, DISCOVER, IMPORTS, MODEL_REFS, PROMPTS, AI_SERVICES, PROVIDERS, DEPS_DEV,
)


def for_rule(rule_id: str) -> tuple[str, ...]:
    """The names of the sources that can raise a finding of this rule's family."""
    return tuple(s.name for s in ALL if any(rule_id.startswith(family) for family in s.families))


def count(result: "ScanResult | None", source: Source, judged: Iterable["Component"],
          findings: Iterable["Finding"]) -> None:
    """Add to `source`'s coverage in `result`: it looked at the `judged` components and had
    something to say about those a finding names. Without a result there is nothing to record."""
    if result is None:
        return
    flagged = {f.component.key() for f in findings if f.component is not None}
    judged = list(judged)
    entry = result.examine(source.name)
    entry.checked += len(judged)
    entry.with_data += sum(1 for c in judged if c.key() in flagged)
