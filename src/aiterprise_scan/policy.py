"""Policy engine (C33), suppressions with mandatory expiry (C34) and baselines (C35).

    # aibom.policy.yaml
    version: 1
    use_context: commercial          # commercial | internal | research | non-profit
    fail_on: [critical, high]        # exit 1 if any NEW finding has one of these severities
    ignore:
      - rule: ait.pkg.malicious-unpinned
        paths: ["experiments/**"]
    allow_packages: ["pkg:pypi/openai@>=1.40"]
    deny_packages: ["pkg:pypi/litellm@1.82.7"]
    allow_model_licences: [mit, apache-2.0, llama3]
    deny_model_licences: [cc-by-nc-4.0]
    suppressions:                    # expiry mandatory
      - finding: 1a2b3c4d5e6f7a8b    # fingerprint, advisory id, or rule id
        until: 2027-06-30
        reason: "vendor patch scheduled"
        approved_by: security@company
    baseline: .aiterprise/baseline.json

A known-malicious finding is never silenced by `allow_packages` or `ignore`; only an explicit,
expiring suppression of that exact finding can accept it.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, miniyaml
from . import purl as purls
from .model import (
    OWASP_SUPPLY_CHAIN,
    SEVERITIES,
    SEVERITY_RANK,
    Component,
    Evidence,
    Finding,
    ScanResult,
    normalize_name,
)
from .textio import read_text
from .versions import range_contains, versions_equal

POLICY_FILENAMES = ("aibom.policy.yaml", "aibom.policy.yml", "aibom.policy.json", ".aiterprise/policy.yaml")
USE_CONTEXTS = ("commercial", "internal", "research", "non-profit")
KNOWN_KEYS = {
    "version", "use_context", "fail_on", "ignore", "allow_packages", "deny_packages",
    "allow_model_licences", "deny_model_licences", "suppressions", "baseline",
}
NEVER_AUTO_SILENCED = {"ait.pkg.malicious"}
SNYK_DEFAULT_DAYS = 30


def fingerprint(finding: Finding) -> str:
    """The CLI/cloud-shared fingerprint (16 hex; design doc 13 J.2)."""
    return finding.fingerprint


def threshold_set(threshold: str) -> set[str]:
    if threshold == "none":
        return set()
    if threshold not in SEVERITY_RANK:
        raise ValueError(f"unknown severity {threshold!r}")
    return {s for s in SEVERITIES if SEVERITY_RANK[s] >= SEVERITY_RANK[threshold]}


def _parse_date(value: Any) -> dt.date | None:
    if isinstance(value, dt.date):
        return value
    if not value:
        return None
    text = str(value).strip()
    try:
        return dt.date.fromisoformat(text[:10])
    except ValueError:
        return None


@dataclass
class PackagePattern:
    raw: str
    ecosystem: str | None
    name: str
    spec: str | None

    @classmethod
    def parse(cls, raw: str) -> "PackagePattern":
        text = str(raw).strip()
        if not text.startswith("pkg:"):
            raise ValueError(f"package pattern must be a purl (pkg:type/name[@version-or-range]): {raw!r}")
        body = text[4:]
        ptype, _, rest = body.partition("/")
        spec = None
        # the range part may itself contain '@' only after the name; split on the last '@'
        at = rest.rfind("@")
        if at > 0:
            rest, spec = rest[:at], rest[at + 1:] or None
        parsed = purls.parse(f"pkg:{ptype}/{rest}")
        if parsed is None:
            raise ValueError(f"cannot parse package pattern {raw!r}")
        return cls(text, parsed.ecosystem, parsed.full_name, spec)

    def matches(self, comp: Component) -> bool:
        if comp.ctype != "library" or (self.ecosystem and comp.ecosystem != self.ecosystem):
            return False
        want = normalize_name(self.name, self.ecosystem)
        have = normalize_name(comp.name, comp.ecosystem)
        if not fnmatch.fnmatchcase(have, want):
            return False
        spec = self.spec
        if not spec or spec == "*":
            return True
        if not comp.version:
            return False  # a range-only component cannot be proven to match a versioned pattern
        if spec[0] in "<>=!~^" or "," in spec or "*" in spec:
            if spec.startswith("==") and "," not in spec and "*" not in spec:
                return versions_equal(comp.ecosystem, spec[2:], comp.version)
            return bool(range_contains(comp.ecosystem, spec, comp.version))
        return versions_equal(comp.ecosystem, spec, comp.version)


@dataclass
class Suppression:
    until: dt.date
    reason: str
    finding: str | None = None  # fingerprint | advisory id | rule id
    rule: str | None = None
    advisory: str | None = None
    fingerprint: str | None = None
    path: str | None = None  # glob on the finding location path
    approved_by: str | None = None
    origin: str = "policy"

    def expired(self, today: dt.date) -> bool:
        return today > self.until

    def matches(self, f: Finding) -> bool:
        ids = {f.fingerprint.lower(), f.rule_id.lower()}
        if f.advisory_id:
            ids.add(f.advisory_id.lower())
        for e in f.evidence:
            if e.record:
                ids.add(e.record.lower())
            for alias in e.detail.get("aliases") or []:
                ids.add(str(alias).lower())
        if self.finding and self.finding.lower() not in ids:
            return False
        if self.fingerprint and self.fingerprint.lower() != f.fingerprint:
            return False
        if self.rule and not fnmatch.fnmatchcase(f.rule_id, self.rule):
            return False
        if self.advisory and self.advisory.lower() not in ids:
            return False
        if self.path:
            loc = f.location.path if f.location else ""
            if self.origin == "snyk":
                if self.path != "*" and (not f.component or f.component.name.lower() not in self.path.lower()):
                    return False
            elif not fnmatch.fnmatchcase(loc, self.path):
                return False
        return any((self.finding, self.fingerprint, self.rule, self.advisory, self.path))

    def to_dict(self) -> dict[str, Any]:
        d = {"until": self.until.isoformat(), "reason": self.reason, "origin": self.origin}
        if self.approved_by:
            d["approved_by"] = self.approved_by
        return d


@dataclass
class IgnoreRule:
    rule: str
    paths: list[str] = field(default_factory=list)

    def matches(self, f: Finding) -> bool:
        if not fnmatch.fnmatchcase(f.rule_id, self.rule):
            return False
        if not self.paths:
            return True
        loc = f.location.path if f.location else ""
        return any(fnmatch.fnmatchcase(loc, p) for p in self.paths)


@dataclass
class Policy:
    path: str | None = None
    version: int = 1
    use_context: str = "commercial"
    fail_on: set[str] = field(default_factory=lambda: {"critical", "high"})
    ignore: list[IgnoreRule] = field(default_factory=list)
    allow_packages: list[PackagePattern] = field(default_factory=list)
    deny_packages: list[PackagePattern] = field(default_factory=list)
    allow_model_licences: list[str] = field(default_factory=list)
    deny_model_licences: list[str] = field(default_factory=list)
    suppressions: list[Suppression] = field(default_factory=list)
    baseline: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def find_policy(root: Path) -> Path | None:
    base = root if root.is_dir() else root.parent
    for name in POLICY_FILENAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def _as_list(value: Any, key: str, errors: list[str]) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    errors.append(f"{key}: expected a list")
    return []


def parse_policy(doc: Any, path: str | None = None) -> Policy:
    pol = Policy(path=path)
    if doc is None:
        return pol
    if not isinstance(doc, dict):
        pol.errors.append("policy must be a mapping")
        return pol
    for key in doc:
        if key not in KNOWN_KEYS:
            pol.warnings.append(f"unknown key {key!r} (ignored)")
    version = doc.get("version", 1)
    if version != 1:
        pol.errors.append(f"version: unsupported policy version {version!r} (expected 1)")
    ctx = doc.get("use_context", "commercial")
    if ctx not in USE_CONTEXTS:
        pol.errors.append(f"use_context: {ctx!r} is not one of {', '.join(USE_CONTEXTS)}")
    else:
        pol.use_context = ctx
    if "fail_on" in doc:
        fo = doc["fail_on"]
        if isinstance(fo, str):
            try:
                pol.fail_on = threshold_set(fo)
            except ValueError as err:
                pol.errors.append(f"fail_on: {err}")
        elif isinstance(fo, list):
            bad = [s for s in fo if s not in SEVERITIES]
            if bad:
                pol.errors.append(f"fail_on: unknown severities {bad}")
            pol.fail_on = {s for s in fo if s in SEVERITIES}
        else:
            pol.errors.append("fail_on: expected a severity or a list of severities")
    for i, item in enumerate(_as_list(doc.get("ignore"), "ignore", pol.errors)):
        if not isinstance(item, dict) or not item.get("rule"):
            pol.errors.append(f"ignore[{i}]: needs a 'rule'")
            continue
        pol.ignore.append(IgnoreRule(str(item["rule"]), [str(p) for p in _as_list(item.get("paths"), f"ignore[{i}].paths", pol.errors)]))
    for key in ("allow_packages", "deny_packages"):
        for raw in _as_list(doc.get(key), key, pol.errors):
            try:
                getattr(pol, key).append(PackagePattern.parse(raw))
            except ValueError as err:
                pol.errors.append(f"{key}: {err}")
    for key in ("allow_model_licences", "deny_model_licences"):
        setattr(pol, key, [str(x).lower() for x in _as_list(doc.get(key), key, pol.errors)])
    for i, item in enumerate(_as_list(doc.get("suppressions"), "suppressions", pol.errors)):
        if not isinstance(item, dict):
            pol.errors.append(f"suppressions[{i}]: expected a mapping")
            continue
        until = _parse_date(item.get("until"))
        if until is None:
            pol.errors.append(f"suppressions[{i}]: 'until' (YYYY-MM-DD) is mandatory")
            continue
        if not item.get("reason"):
            pol.errors.append(f"suppressions[{i}]: 'reason' is mandatory")
            continue
        selectors = {k: item.get(k) for k in ("finding", "rule", "advisory", "fingerprint", "path")}
        if not any(selectors.values()):
            pol.errors.append(f"suppressions[{i}]: needs one of finding/rule/advisory/fingerprint/path")
            continue
        pol.suppressions.append(Suppression(
            until=until,
            reason=str(item["reason"]),
            approved_by=str(item["approved_by"]) if item.get("approved_by") else None,
            **{k: (str(v) if v is not None else None) for k, v in selectors.items()},
        ))
    if doc.get("baseline"):
        pol.baseline = str(doc["baseline"])
    return pol


def load_policy(path: Path) -> Policy:
    text = read_text(path)
    try:
        doc = json.loads(text) if path.suffix == ".json" else miniyaml.load(text)
    except (ValueError, miniyaml.YAMLError) as err:
        pol = Policy(path=str(path))
        pol.errors.append(f"cannot parse: {err}")
        return pol
    return parse_policy(doc, str(path))


def load_snyk(path: Path, today: dt.date | None = None) -> list[Suppression]:
    """Import a `.snyk` file's `ignore` section (id → path → {reason, expires, created})."""
    today = today or dt.date.today()
    doc = miniyaml.load(read_text(path)) or {}
    out: list[Suppression] = []
    for vid, entries in (doc.get("ignore") or {}).items():
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            for dep_path, meta in entry.items():
                meta = meta or {}
                until = _parse_date(meta.get("expires"))
                if until is None:
                    created = _parse_date(meta.get("created")) or today
                    until = created + dt.timedelta(days=SNYK_DEFAULT_DAYS)
                out.append(Suppression(
                    until=until,
                    reason=str(meta.get("reason") or "imported from .snyk"),
                    advisory=str(vid),
                    path=str(dep_path),
                    origin="snyk",
                ))
    return out


# --------------------------------------------------------------------------------------------
# Baselines
# --------------------------------------------------------------------------------------------

def write_baseline(result: ScanResult, path: Path) -> int:
    entries = {
        f.fingerprint: {"rule_id": f.rule_id, "severity": f.severity, "title": f.title}
        for f in result.findings
        if f.status in ("new", "acknowledged")
    }
    doc = {
        "schema": "aiterprise-baseline/1",
        "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": __version__,
        "fingerprints": dict(sorted(entries.items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    return len(entries)


def load_baseline(path: Path) -> set[str]:
    doc = json.loads(read_text(path))
    fps = doc.get("fingerprints", {})
    return set(fps if isinstance(fps, (dict, list)) else [])


# --------------------------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------------------------

def denied_package_findings(components: list[Component], policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    for comp in components:
        for pat in policy.deny_packages:
            if pat.matches(comp):
                out.append(Finding(
                    rule_id="ait.policy.denied-package",
                    title=f"Package denied by policy ({pat.raw})",
                    severity="high",
                    verdict="suspicious",
                    confidence=100,
                    component=comp,
                    evidence=[Evidence("policy", pat.raw, None, {"policy": policy.path})],
                    remediation="Remove the package or change the policy with a reviewed exception.",
                    maps_to=[OWASP_SUPPLY_CHAIN],
                ))
                break
    return out


def apply(result: ScanResult, policy: Policy, baseline: set[str] | None = None,
          today: dt.date | None = None) -> list[Finding]:
    """Set finding statuses and return the findings that fail the gate."""
    today = today or dt.date.today()
    expired_notes: set[str] = set()
    for f in result.findings:
        if f.status != "new":
            continue
        auto_ok = f.rule_id not in NEVER_AUTO_SILENCED
        if auto_ok:
            rule = next((r for r in policy.ignore if r.matches(f)), None)
            if rule is not None:
                f.status = "suppressed"
                f.suppression = {"reason": f"policy ignore ({rule.rule})", "origin": "policy"}
                continue
            if f.component is not None and any(p.matches(f.component) for p in policy.allow_packages):
                f.status = "suppressed"
                f.suppression = {"reason": "allow_packages", "origin": "policy"}
                continue
        for sup in policy.suppressions:
            if not sup.matches(f):
                continue
            if sup.expired(today):
                expired_notes.add(f"suppression for {sup.finding or sup.advisory or sup.rule or sup.path} "
                                  f"expired {sup.until.isoformat()}")
                continue
            f.status = "suppressed"
            f.suppression = sup.to_dict()
            break
        if f.status == "new" and baseline and f.fingerprint in baseline:
            f.status = "acknowledged"
            f.suppression = {"reason": "baseline", "origin": "baseline"}
    result.notes.extend(sorted(expired_notes))
    return [f for f in result.findings if f.status == "new" and f.severity in policy.fail_on]
