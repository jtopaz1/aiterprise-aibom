"""Core data model shared by every analyzer: components, evidence, findings, scan results.

Every finding is *claim + evidence + remediation + quality metadata* (design doc 13 §4.3).
Analyzers never print; they return these objects and the reporters render them.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

SEVERITIES = ("critical", "high", "medium", "low", "info")
# info=0 … critical=4, so "a >= b" reads naturally.
SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES))}

VERDICTS = ("malicious", "suspicious", "benign", "unknown")

# Component types. `library` covers every package; `ai` on the component says whether it is in
# the AI taxonomy. `model` / `dataset` are referenced artefacts (e.g. a Hugging Face id),
# `model-file` is a file on disk.
CTYPES = (
    "library",
    "model-file",
    "model",
    "dataset",
    "mcp-server",
    "mcp-config",
    "agent-skill",
    "ai-endpoint",
)

FINDING_STATES = ("new", "acknowledged", "suppressed", "resolved", "withdrawn")

OWASP_SUPPLY_CHAIN = "LLM03:2025 Supply Chain"
OWASP_POISONING = "LLM04:2025 Data and Model Poisoning"
OWASP_PROMPT_INJECTION = "LLM01:2025 Prompt Injection"
OWASP_EXCESSIVE_AGENCY = "LLM06:2025 Excessive Agency"
OWASP_SENSITIVE_INFO = "LLM02:2025 Sensitive Information Disclosure"


def severity_at_least(severity: str, threshold: str) -> bool:
    """True when `severity` is as severe as `threshold` or more."""
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(threshold, 0)


def max_severity(severities) -> str | None:
    best = None
    for sev in severities:
        if best is None or SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(best, 0):
            best = sev
    return best


_PEP503 = re.compile(r"[-_.]+")


def normalize_name(name: str, ecosystem: str | None) -> str:
    """Canonical package name used for matching (PEP 503 for PyPI, lower-case for npm)."""
    if ecosystem == "pypi":
        return _PEP503.sub("-", name).lower()
    if ecosystem == "npm":
        return name.lower()
    return name


@dataclass
class Location:
    path: str  # relative to the scan root, forward slashes
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"path": self.path}
        if self.line:
            d["line"] = self.line
        return d


@dataclass
class Component:
    name: str
    ctype: str = "library"
    version: str | None = None  # exact version only; None when unknown or only a range is declared
    ecosystem: str | None = None  # pypi | npm | huggingface | cargo | ...
    version_spec: str | None = None  # the declared range when `version` is not exact
    locations: list[Location] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)  # algorithm -> lowercase hex
    licence: str | None = None  # declared licence id / expression / tag
    ai: bool = False  # True when the component is in the AI taxonomy
    source: str = ""  # lockfile | manifest | import | bom | config | file | code-ref
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # models, datasets, MCP servers/configs, skills and AI endpoints are AI components by
        # definition; only libraries need the taxonomy to decide
        if self.ctype != "library":
            self.ai = True

    @property
    def purl(self) -> str | None:
        explicit = self.properties.get("purl")
        if explicit:
            return explicit
        if not self.ecosystem:
            return None
        eco = self.ecosystem
        if eco == "npm":
            if self.name.startswith("@") and "/" in self.name:
                scope, _, pkg = self.name.partition("/")
                base = f"pkg:npm/{quote(scope)}/{quote(pkg)}"
            else:
                base = f"pkg:npm/{quote(self.name)}"
        elif eco == "pypi":
            base = f"pkg:pypi/{normalize_name(self.name, 'pypi')}"
        elif eco == "huggingface":
            base = f"pkg:huggingface/{self.name}"
        else:
            base = f"pkg:{eco}/{quote(self.name, safe='/')}"
        return f"{base}@{quote(self.version, safe='')}" if self.version else base

    @property
    def display(self) -> str:
        if self.purl:
            return self.purl
        if self.version:
            return f"{self.name}@{self.version}"
        return self.name

    def key(self) -> tuple:
        """Identity used to merge the same component found in several places."""
        return (
            self.ctype,
            self.ecosystem,
            normalize_name(self.name, self.ecosystem),
            self.version,
            # two different ranges are two different questions ("can this resolve to a bad
            # version?"), so they are not merged when no exact version is known
            None if self.version else (self.version_spec or None),
            self.properties.get("path") if self.ctype == "model-file" else None,
        )

    def add_location(self, loc: Location) -> None:
        if all((l.path, l.line) != (loc.path, loc.line) for l in self.locations):
            self.locations.append(loc)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "type": self.ctype}
        for key in ("version", "ecosystem", "version_spec", "licence"):
            value = getattr(self, key)
            if value:
                d[key] = value
        if self.purl:
            d["purl"] = self.purl
        d["ai"] = self.ai
        if self.source:
            d["source"] = self.source
        if self.locations:
            d["locations"] = [str(l) for l in self.locations]
        if self.hashes:
            d["hashes"] = dict(self.hashes)
        props = {k: v for k, v in self.properties.items() if k != "purl"}
        if props:
            d["properties"] = props
        return d


@dataclass
class Evidence:
    source: str  # osv | ait-malicious | kev | ait-rules | ait-licence | ...
    record: str | None = None  # advisory / rule / record id
    url: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"source": self.source}
        if self.record:
            d["record"] = self.record
        if self.url:
            d["url"] = self.url
        if self.detail:
            d.update({k: v for k, v in self.detail.items() if k not in d})
        return d


@dataclass
class Finding:
    rule_id: str  # e.g. ait.pkg.malicious
    title: str
    severity: str
    verdict: str = "unknown"
    confidence: int = 50  # 0-100
    component: Component | None = None
    location: Location | None = None
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str = ""
    advisory_id: str | None = None
    kev: bool = False
    maps_to: list[str] = field(default_factory=list)  # OWASP LLM Top 10 2025 tags
    status: str = "new"
    suppression: dict[str, Any] | None = None
    # Extra discriminator for the fingerprint when one rule can fire several times on the same
    # subject and file (e.g. two different secrets in one config). Never put raw secrets here.
    discriminator: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {self.verdict!r}")
        if self.location is None and self.component is not None and self.component.locations:
            self.location = self.component.locations[0]

    def withdraw(self, when: str | None) -> None:
        """The advisory behind this finding was withdrawn: keep the finding (same fingerprint, so
        history follows it) but take it out of every active count and gate (design doc 13 §4.3)."""
        self.status = "withdrawn"
        self.severity = "info"
        self.verdict = "unknown"
        self.title = f"[withdrawn advisory] {self.title}"
        self.suppression = {"reason": f"advisory withdrawn{' ' + when[:10] if when else ''}", "origin": "advisory"}
        if self.evidence:
            self.evidence[0].detail["withdrawn"] = when[:10] if when else True

    @property
    def subject(self) -> str:
        if self.component is None:
            return ""
        return self.component.purl or self.component.name

    @property
    def fingerprint(self) -> str:
        """Stable 16-hex id. Line numbers are excluded so edits elsewhere do not churn it.

        The cloud's `app.aibom_finding.fingerprint char(16)` uses the same algorithm so local
        suppressions/baselines and server state map 1:1 (design doc 13, J.2).
        """
        parts = [
            self.rule_id,
            self.subject,
            self.advisory_id or "",
            self.location.path if self.location else "",
            self.discriminator,
        ]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "verdict": self.verdict,
            "confidence": self.confidence,
        }
        if self.component is not None:
            d["component"] = self.component.to_dict()
        if self.location is not None:
            d["location"] = str(self.location)
        if self.advisory_id:
            d["advisory_id"] = self.advisory_id
        if self.kev:
            d["kev"] = True
        d["evidence"] = [e.to_dict() for e in self.evidence]
        if self.remediation:
            d["remediation"] = self.remediation
        if self.maps_to:
            d["maps_to"] = list(self.maps_to)
        d["status"] = self.status
        if self.suppression:
            d["suppression"] = dict(self.suppression)
        return d


def not_analysable(area: str, path: str, what: str, reason: str, component: "Component | None" = None) -> Finding:
    """A file the scanner had to skip. Never a clean result: whatever it holds was not checked
    ("no match" is not "never checked"), so the gap is reported where the file is."""
    return Finding(
        rule_id=f"ait.{area}.not-analysable",
        title=f"{what} was not analysed ({reason}); its contents are unknown, not clean",
        severity="medium",
        verdict="unknown",
        confidence=90,
        component=component,
        location=Location(path),
        evidence=[Evidence("ait-scan", "not-analysable", None, {"reason": reason})],
        remediation="Check this file by hand or with a tool that can read it; the scan says nothing about it.",
        discriminator=path,
    )


@dataclass
class Examined:
    """Per-source accounting: "no match" is not "never checked" (REPORT §8 rule)."""

    source: str
    checked: int = 0
    with_data: int = 0
    errors: int = 0
    skipped: str | None = None  # reason the source was not consulted (offline, no network, ...)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"checked": self.checked, "with_data": self.with_data}
        if self.errors:
            d["errors"] = self.errors
        if self.skipped:
            d["skipped"] = self.skipped
        return d


# a finding in one of these states no longer counts towards the severity totals
INACTIVE_STATUSES = ("suppressed", "withdrawn", "resolved")


@dataclass
class ScanResult:
    target: str
    mode: str  # online | offline
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    examined: dict[str, Examined] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    started_at: str = ""
    duration_s: float = 0.0
    files_walked: int = 0
    policy_path: str | None = None
    exit_code: int = 0
    # attribution notices from data sources (SecDB `notices[]`), reproduced in full wherever the
    # data is shown (`14a` §2)
    notices: list[dict[str, Any]] = field(default_factory=list)

    def add_notices(self, notices: list[dict[str, Any]] | None) -> None:
        have = {n.get("id") for n in self.notices}
        for n in notices or []:
            if isinstance(n, dict) and n.get("text") and n.get("id") not in have:
                self.notices.append({k: n[k] for k in ("id", "text", "url") if n.get(k)})
                have.add(n.get("id"))

    def examine(self, source: str) -> Examined:
        if source not in self.examined:
            self.examined[source] = Examined(source)
        return self.examined[source]

    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status not in INACTIVE_STATUSES]

    def severity_counts(self, active_only: bool = True) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.active_findings() if active_only else self.findings:
            counts[f.severity] += 1
        return counts


def merge_components(components: list[Component]) -> list[Component]:
    """Merge duplicates (same key), keeping every location and the richest metadata."""
    merged: dict[tuple, Component] = {}
    for comp in components:
        k = comp.key()
        existing = merged.get(k)
        if existing is None:
            merged[k] = comp
            continue
        for loc in comp.locations:
            existing.add_location(loc)
        for alg, value in comp.hashes.items():
            existing.hashes.setdefault(alg, value)
        existing.licence = existing.licence or comp.licence
        existing.ai = existing.ai or comp.ai
        existing.version_spec = existing.version_spec or comp.version_spec
        for pk, pv in comp.properties.items():
            existing.properties.setdefault(pk, pv)
    return list(merged.values())


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id, f.subject, str(f.location or "")),
    )
