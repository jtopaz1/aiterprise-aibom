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
    allow_package_licences: [mit, apache-2.0, bsd-*, isc]
    deny_package_licences: [agpl-3.0, sspl-1.0]
    suppressions:                    # expiry mandatory
      - finding: 1a2b3c4d5e6f7a8b    # fingerprint, advisory id, or rule id
        until: 2027-06-30
        reason: "vendor patch scheduled"
        approved_by: security@company
    baseline: .aiterprise/baseline.json

A known-malicious finding (verdict `malicious`: a MAL- record, a code-executing pickle, a poisoned
MCP instruction, ...) is never silenced by `allow_packages`, `ignore`, a rule-, path- or
advisory-wide suppression, or a baseline (which never expires); only an expiring suppression that
names its fingerprint accepts it.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, miniyaml, sources
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
    "allow_model_licences", "deny_model_licences", "allow_package_licences", "deny_package_licences",
    "suppressions", "baseline",
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

    def names(self, f: Finding) -> bool:
        """True when this suppression selects `f` by its fingerprint, not by rule/path/advisory."""
        return f.fingerprint in {(self.fingerprint or "").lower(), (self.finding or "").lower()}

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
    allow_package_licences: list[str] = field(default_factory=list)
    deny_package_licences: list[str] = field(default_factory=list)
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
    for key in ("allow_model_licences", "deny_model_licences", "allow_package_licences", "deny_package_licences"):
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
    return loads_policy(read_text(path), str(path), as_json=path.suffix == ".json")


def loads_policy(text: str, path: str | None = None, as_json: bool = False) -> Policy:
    try:
        doc = json.loads(text) if as_json else miniyaml.load(text)
    except (ValueError, miniyaml.YAMLError) as err:
        pol = Policy(path=path)
        pol.errors.append(f"cannot parse: {err}")
        return pol
    return parse_policy(doc, path)


LOCAL_SUPPRESSIONS = Path(".aiterprise") / "suppressions.json"
MAX_SUPPRESSION_DAYS = 365


def _local_file(root: Path) -> Path:
    return (root if root.is_dir() else root.parent) / LOCAL_SUPPRESSIONS


def merge_local_suppressions(pol: Policy, root: Path | None) -> None:
    """Add `.aiterprise/suppressions.json` (written by `aiterprise-scan ui`) to the policy.

    Same rules as the policy file: an expiry and a reason are mandatory. Commit the file so CI
    applies the same acceptances."""
    if root is None:
        return
    path = _local_file(root)
    if not path.is_file():
        return
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        pol.errors.append(f"{path}: cannot parse: {err}")
        return
    extra = parse_policy({"suppressions": doc.get("suppressions") if isinstance(doc, dict) else None}, str(path))
    pol.errors.extend(f"{path}: {e}" for e in extra.errors)
    for sup in extra.suppressions:
        sup.origin = "local"
        pol.suppressions.append(sup)


def add_local_suppression(root: Path, fingerprint: str, until: str, reason: str, approved_by: str | None = None,
                          today: dt.date | None = None) -> Path:
    """Append one fingerprint suppression to the project's local file. Raises ValueError."""
    today = today or dt.date.today()
    fingerprint = fingerprint.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
        raise ValueError("a suppression names a finding by its 16-hex fingerprint")
    day = _parse_date(until)
    if day is None:
        raise ValueError("until must be a date (YYYY-MM-DD)")
    if day <= today:
        raise ValueError("until must be in the future")
    if (day - today).days > MAX_SUPPRESSION_DAYS:
        raise ValueError(f"until may be at most {MAX_SUPPRESSION_DAYS} days ahead")
    reason = reason.strip()
    if not reason:
        raise ValueError("a reason is mandatory")
    path = _local_file(root)
    try:
        doc = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except ValueError:
        raise ValueError(f"{path} is not valid JSON; fix or remove it first") from None
    items = [s for s in (doc.get("suppressions") or []) if isinstance(s, dict) and s.get("finding") != fingerprint]
    entry = {"finding": fingerprint, "until": day.isoformat(), "reason": reason[:500],
             "created": today.isoformat(), "origin": "aiterprise-scan ui"}
    if approved_by and approved_by.strip():
        entry["approved_by"] = approved_by.strip()[:200]
    items.append(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"version": 1, "suppressions": items}, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


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

def package_policy_findings(components: list[Component], policy: Policy, result=None) -> list[Finding]:
    """The policy's package rules: `deny_packages`, and each package's licence against
    `deny_package_licences` and `allow_package_licences`. Given a `result`, records the coverage once
    for all of them; a policy with none of these lists is not a consulted source."""
    if not (policy.deny_packages or policy.deny_package_licences or policy.allow_package_licences):
        return []
    out = _denied(components, policy) if policy.deny_packages else []
    out += _licence_findings(components, policy, result)
    sources.count(result, sources.POLICY, (c for c in components if c.ctype == "library"), out)
    return out


# --------------------------------------------------------------------------------------------
# Package licences: SPDX expressions against the allow and deny lists
# --------------------------------------------------------------------------------------------

_SPDX_TOKEN = re.compile(r"\(|\)|[^\s()]+")
_SPDX_OPS = ("AND", "OR", "WITH")


def _spdx_tree(expr: str) -> tuple:
    """`("id", text)`, `("with", licence, exception)`, `("and", [...])` or `("or", [...])`. Text that
    is not an SPDX expression ("SEE LICENSE IN LICENSE.md") is one id: it matches only itself."""
    tokens = _SPDX_TOKEN.findall(expr)
    pos = 0

    def peek() -> str | None:
        return tokens[pos].upper() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def parse(op: str) -> tuple:  # OR binds loosest, then AND
        parts = [parse("AND") if op == "OR" else parse_with()]
        while peek() == op:
            take()
            parts.append(parse("AND") if op == "OR" else parse_with())
        return parts[0] if len(parts) == 1 else (op.lower(), parts)

    def parse_with() -> tuple:
        node = parse_atom()
        if peek() != "WITH":
            return node
        take()
        if node[0] != "id" or peek() in (None, "(", ")", *_SPDX_OPS):
            raise ValueError
        return ("with", node[1], take())

    def parse_atom() -> tuple:
        tok = peek()
        if tok in (None, ")", *_SPDX_OPS):
            raise ValueError
        take()
        if tok != "(":
            return ("id", tokens[pos - 1])
        node = parse("OR")
        if peek() != ")":
            raise ValueError
        take()
        return node

    try:
        tree = parse("OR")
        if pos != len(tokens):
            raise ValueError
        return tree
    except ValueError:
        return ("id", expr.strip())


def _canon_licence(value: str) -> str:
    text = " ".join(value.lower().split())
    return text[:-1] + "-or-later" if text.endswith("+") else text


def _licence_matches(licence: str, pattern: str) -> bool:
    """A policy entry is a glob (`gpl-*`); a bare family (`gpl-3.0`) covers its `-only` and
    `-or-later` ids, and `gpl-3.0-only` covers the deprecated bare `GPL-3.0`. Case is ignored."""
    lic, pat = _canon_licence(licence), _canon_licence(pattern)
    return (fnmatch.fnmatchcase(lic, pat) or re.sub(r"-(only|or-later)$", "", lic) == pat
            or pat == lic + "-only")


def _leaf_texts(node: tuple) -> list[str]:
    """What a leaf can be matched as: the licence, and with an exception also the whole phrase."""
    return [node[1]] if node[0] == "id" else [f"{node[1]} WITH {node[2]}", node[1]]


def _denied_by(node: tuple, deny: list[str]) -> str | None:
    """The deny entry every way of meeting the expression runs into; None if one way avoids them."""
    if node[0] in ("id", "with"):
        return next((p for text in _leaf_texts(node) for p in deny if _licence_matches(text, p)), None)
    hits = [_denied_by(child, deny) for child in node[1]]
    if node[0] == "and":
        return next((h for h in hits if h), None)
    return hits[0] if all(hits) else None  # OR: a choice, denied only if every choice is


def _allowed_by(node: tuple, allow: list[str]) -> bool:
    if node[0] in ("id", "with"):
        return any(_licence_matches(text, p) for text in _leaf_texts(node) for p in allow)
    results = [_allowed_by(child, allow) for child in node[1]]
    return all(results) if node[0] == "and" else any(results)


def licence_verdict(expr: str, allow: list[str], deny: list[str]) -> tuple[str | None, str | None]:
    """`("denied", entry)`, `("not-allowed", None)` or `(None, None)` for one package licence. OR
    is a choice (one acceptable licence is enough), AND needs every part; denied wins."""
    tree = _spdx_tree(expr)
    if deny:
        hit = _denied_by(tree, deny)
        if hit:
            return "denied", hit
    if allow and not _allowed_by(tree, allow):
        return "not-allowed", None
    return None, None


def _licence_findings(components: list[Component], policy: Policy, result=None) -> list[Finding]:
    allow, deny = policy.allow_package_licences, policy.deny_package_licences
    if not (allow or deny):
        return []
    out: list[Finding] = []
    unknown: list[str] = []
    for comp in components:
        if comp.ctype != "library":
            continue
        if not comp.licence:
            unknown.append(comp.name)
            continue
        kind, entry = licence_verdict(comp.licence, allow, deny)
        if kind == "denied":
            out.append(Finding(
                rule_id="ait.policy.denied-licence",
                title=f"Package licence denied by policy: {comp.licence} (matches {entry})",
                severity="high", verdict="suspicious", confidence=90, component=comp,
                evidence=[Evidence("policy", entry, None, {"policy": policy.path, "list": "deny_package_licences",
                                                           "matched": entry, "licence": comp.licence})],
                remediation="Replace the package, or change the policy with a reviewed exception.",
                maps_to=[OWASP_SUPPLY_CHAIN],
            ))
        elif kind == "not-allowed":
            out.append(Finding(
                rule_id="ait.policy.licence-not-allowed",
                title=f"Package licence not in allow_package_licences: {comp.licence}",
                severity="medium", verdict="suspicious", confidence=90, component=comp,
                evidence=[Evidence("policy", "allow_package_licences", None,
                                   {"policy": policy.path, "list": "allow_package_licences", "licence": comp.licence})],
                remediation="Check the licence's terms; add it to allow_package_licences if acceptable, or replace "
                            "the package.",
                maps_to=[OWASP_SUPPLY_CHAIN],
            ))
    if allow and unknown and result is not None:
        names = list(dict.fromkeys(unknown))
        result.notes.append(f"policy: {len(names)} package(s) have no known licence, so allow_package_licences could "
                            "not be checked for them: " + ", ".join(names[:5]) + (" …" if len(names) > 5 else ""))
    return out


def _denied(components: list[Component], policy: Policy) -> list[Finding]:
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


def is_protected(f: Finding) -> bool:
    """Known-malicious: accepted only by a suppression that names its fingerprint."""
    return f.verdict == "malicious" or f.rule_id in NEVER_AUTO_SILENCED


def apply(result: ScanResult, policy: Policy, baseline: set[str] | None = None,
          today: dt.date | None = None) -> list[Finding]:
    """Set finding statuses and return the findings that fail the gate."""
    today = today or dt.date.today()
    notes: set[str] = set()
    for f in result.findings:
        if f.status != "new":
            continue
        protected = is_protected(f)
        if not protected:
            rule = next((r for r in policy.ignore if r.matches(f)), None)
            if rule is not None:
                f.status = "suppressed"
                f.suppression = {"reason": f"policy ignore ({rule.rule})", "origin": "policy"}
                continue
            if f.component is not None and any(p.matches(f.component) for p in policy.allow_packages):
                f.status = "suppressed"
                f.suppression = {"reason": "allow_packages", "origin": "policy"}
                continue
        refused = False
        for sup in policy.suppressions:
            if not sup.matches(f):
                continue
            if protected and not sup.names(f):
                refused = True
                continue
            if sup.expired(today):
                notes.add(f"suppression for {sup.finding or sup.advisory or sup.rule or sup.path} "
                          f"expired {sup.until.isoformat()}")
                continue
            f.status = "suppressed"
            f.suppression = sup.to_dict()
            break
        if f.status == "new" and baseline and f.fingerprint in baseline:
            if protected:
                refused = True
            else:
                f.status = "acknowledged"
                f.suppression = {"reason": "baseline", "origin": "baseline"}
        if refused and f.status == "new":
            notes.add(f"known-malicious finding {f.fingerprint} ({f.rule_id}) was not silenced by a rule-, "
                      "path- or advisory-wide suppression or a baseline; only an expiring suppression "
                      "naming this fingerprint accepts it")
    result.notes.extend(sorted(notes))
    return [f for f in result.findings if f.status == "new" and f.severity in policy.fail_on]
