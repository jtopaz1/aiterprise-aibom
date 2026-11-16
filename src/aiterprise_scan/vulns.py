"""Vulnerability judgement via OSV (C19) with CISA KEV prioritisation (C20).

Flow: OSV `querybatch` (ids only) for every component with an exact version → per-advisory
detail fetch (cached) → alias-grouped de-duplication → severity (GHSA rating, else CVSS v3 base
score) → KEV membership upgrades to critical. `MAL-` ids from OSV become malicious findings with
the same fingerprint as the bundled snapshot's, so the two sources merge instead of doubling.
"""

from __future__ import annotations

import math
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache

from . import data, net, sources
from .cache import Cache
from .intel_malicious import REMEDIATION as MAL_REMEDIATION
from .model import (
    OWASP_SUPPLY_CHAIN,
    SEVERITY_RANK,
    Component,
    Evidence,
    Finding,
    ScanResult,
    normalize_name,
)
from .versions import pep440_parse, semver_parse

OSV_API = "https://api.osv.dev/v1"
OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "cargo": "crates.io",
    "golang": "Go",
    "gem": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
}
BATCH_SIZE = 1000
DETAIL_WORKERS = 8


# --------------------------------------------------------------------------------------------
# KEV
# --------------------------------------------------------------------------------------------

@lru_cache(maxsize=1)
def kev_catalog() -> dict:
    return data.load("kev.json")


def kev_entry(cve: str) -> dict | None:
    return kev_catalog().get("cves", {}).get(cve)


# --------------------------------------------------------------------------------------------
# CVSS v3.x base score
# --------------------------------------------------------------------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        av, ac, ui = _W["AV"][parts["AV"]], _W["AC"][parts["AC"]], _W["UI"][parts["UI"]]
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        c, i, a = (_W["CIA"][parts[k]] for k in ("C", "I", "A"))
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


_GHSA_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def advisory_severity(doc: dict) -> tuple[str, str]:
    """(severity, basis)"""
    db = doc.get("database_specific") or {}
    sev = _GHSA_SEVERITY.get(str(db.get("severity", "")).upper())
    if sev:
        return sev, "ghsa-rating"
    best: float | None = None
    for s in doc.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_base_score(str(s.get("score", "")))
            if score is not None and (best is None or score > best):
                best = score
    for aff in doc.get("affected") or []:
        for s in aff.get("severity") or []:
            if str(s.get("type", "")).startswith("CVSS_V3"):
                score = cvss3_base_score(str(s.get("score", "")))
                if score is not None and (best is None or score > best):
                    best = score
    if best is not None:
        return score_to_severity(best), f"cvss3 {best}"
    return "medium", "default (no rating published)"


# --------------------------------------------------------------------------------------------
# OSV access
# --------------------------------------------------------------------------------------------

@dataclass
class OSVClient:
    cache: Cache
    offline: bool = False
    timeout: float = 20.0

    def query_ids(self, queries: list[tuple[str, str, str]], result: ScanResult | None = None) -> dict[tuple, list[str]]:
        """queries: (osv_ecosystem, name, version) → advisory ids per query."""
        out: dict[tuple, list[str]] = {}
        pending: list[tuple[str, str, str]] = []
        for q in queries:
            cached = self.cache.get("osv-query", "|".join(q), allow_stale=self.offline)
            if cached is not None:
                out[q] = cached
            elif not self.offline:
                pending.append(q)
        for start in range(0, len(pending), BATCH_SIZE):
            chunk = pending[start : start + BATCH_SIZE]
            body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
            resp = net.request_json("POST", f"{OSV_API}/querybatch", body, timeout=self.timeout)
            results = (resp or {}).get("results") or []
            for q, res in zip(chunk, results):
                ids = [v["id"] for v in (res or {}).get("vulns") or [] if v.get("id")]
                token = (res or {}).get("next_page_token")
                while token:
                    page = net.request_json(
                        "POST", f"{OSV_API}/query",
                        {"package": {"ecosystem": q[0], "name": q[1]}, "version": q[2], "page_token": token},
                        timeout=self.timeout,
                    ) or {}
                    ids.extend(v["id"] for v in page.get("vulns") or [] if v.get("id"))
                    token = page.get("next_page_token")
                out[q] = ids
                self.cache.put("osv-query", "|".join(q), ids)
        return out

    def details(self, ids: list[str]) -> dict[str, dict]:
        docs: dict[str, dict] = {}
        missing: list[str] = []
        for vid in ids:
            cached = self.cache.get("osv-vuln", vid, allow_stale=self.offline)
            if cached is not None:
                docs[vid] = cached
            elif not self.offline:
                missing.append(vid)

        def fetch(vid: str) -> tuple[str, dict | None, bool]:
            try:
                return vid, net.request_json("GET", f"{OSV_API}/vulns/{vid}", timeout=self.timeout), True
            except net.NetError:
                # the old copy serves this scan; it is not stored again, or it would count as fresh
                return vid, self.cache.get("osv-vuln", vid, allow_stale=True), False

        if missing:
            with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
                for vid, doc, fetched in pool.map(fetch, missing):
                    if doc:
                        docs[vid] = doc
                        if fetched:
                            self.cache.put("osv-vuln", vid, doc)
        return docs


# --------------------------------------------------------------------------------------------
# Offline advisory subset (AI packages only)
# --------------------------------------------------------------------------------------------

SUBSET_FILE = "vuln-subset.json.gz"


@lru_cache(maxsize=1)
def vuln_subset() -> dict:
    """The bundled OSV advisories for AI-taxonomy packages ({} when the file is not built)."""
    return data.load(SUBSET_FILE) if data.exists(SUBSET_FILE) else {}


def subset_docs(comp: Component) -> list[dict] | None:
    """Advisories the subset holds for this package; None when the package is outside the subset."""
    names = (vuln_subset().get("packages") or {}).get(comp.ecosystem or "")
    if names is None:
        return None
    return names.get(normalize_name(comp.name, comp.ecosystem))


def osv_affects(doc: dict, comp: Component) -> bool | None:
    """OSV range semantics for one exact version: True / False, or None when undecidable."""
    if not comp.version or not comp.ecosystem:
        return None
    cur = _version_key(comp.ecosystem, comp.version)
    if cur is None:
        return None
    want = normalize_name(comp.name, comp.ecosystem)
    undecided = False
    for aff in doc.get("affected") or []:
        pkg = aff.get("package") or {}
        if normalize_name(str(pkg.get("name", "")), comp.ecosystem) != want:
            continue
        for v in aff.get("versions") or []:
            key = _version_key(comp.ecosystem, str(v))
            if key is not None and key == cur:
                return True
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            state = _range_state(comp.ecosystem, rng.get("events") or [], cur)
            if state is None:
                undecided = True
            elif state:
                return True
    return None if undecided else False


_EVENT_ORDER = {"introduced": 0, "fixed": 1, "last_affected": 2}


def _range_state(ecosystem: str, events: list[dict], cur: tuple) -> bool | None:
    parsed = []
    for ev in events:
        for kind in ("introduced", "fixed", "last_affected"):
            if kind not in ev:
                continue
            raw = str(ev[kind])
            if kind == "introduced" and raw == "0":
                parsed.append(((0,), _EVENT_ORDER[kind], kind, None))
                continue
            key = _version_key(ecosystem, raw)
            if key is None:
                return None
            parsed.append(((1, key), _EVENT_ORDER[kind], kind, key))
    affected = False
    for _, _, kind, key in sorted(parsed, key=lambda p: (p[0], p[1])):
        if kind == "introduced" and (key is None or cur >= key):
            affected = True
        elif kind == "fixed" and cur >= key:
            affected = False
        elif kind == "last_affected" and cur > key:
            affected = False
    return affected


def _judge_from_subset(targets: dict[tuple, list[Component]], result: ScanResult, why: str
                       ) -> tuple[dict[tuple, list[str]], dict[str, dict], int]:
    """Advisory ids per query from the bundled subset; returns (ids, docs, packages outside it)."""
    examined = result.examine(sources.OSV_SUBSET.name)
    meta = vuln_subset()
    if not meta:
        examined.skipped = "advisory subset not built (tools/build_vuln_subset.py)"
        return {}, {}, len(targets)
    ids: dict[tuple, list[str]] = {}
    docs: dict[str, dict] = {}
    outside = 0
    for q, comps in targets.items():
        held = subset_docs(comps[0])
        if held is None:
            outside += 1
            continue
        examined.checked += 1
        hit = []
        for d in held:
            if osv_affects(d, comps[0]):
                hit.append(d["id"])
                docs[d["id"]] = d
        if hit:
            examined.with_data += 1
        ids[q] = hit
    built = str(meta.get("generated_at") or "")[:10]
    result.notes.append(
        f"osv: {why}; {examined.checked} AI package(s) judged from the bundled advisory subset "
        f"({meta.get('advisory_count', 0):,} advisories, built {built or 'unknown'})"
        + (f"; {outside} package(s) outside it were not checked" if outside else ""))
    return ids, docs, outside


# --------------------------------------------------------------------------------------------
# Judgement
# --------------------------------------------------------------------------------------------

def _version_key(ecosystem: str, version: str):
    if ecosystem == "pypi":
        return pep440_parse(version)
    if ecosystem == "npm":
        return semver_parse(version)
    return None


def fixed_versions(doc: dict, comp: Component) -> list[str]:
    fixed: list[str] = []
    want = normalize_name(comp.name, comp.ecosystem)
    for aff in doc.get("affected") or []:
        pkg = aff.get("package") or {}
        if normalize_name(pkg.get("name", ""), comp.ecosystem) != want:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
    return fixed


def _next_fix(comp: Component, fixed: list[str]) -> str | None:
    if not comp.version or not fixed or not comp.ecosystem:
        return None
    cur = _version_key(comp.ecosystem, comp.version)
    if cur is None:
        return None
    above = [(k, f) for f in fixed if (k := _version_key(comp.ecosystem, f)) is not None and k > cur]
    if not above:
        return None
    finals = [(k, f) for k, f in above if _is_final(comp.ecosystem, k)]
    return min(finals or above)[1]


def _is_final(ecosystem: str, key: tuple) -> bool:
    """True for a final release (not alpha/beta/rc/dev), so remediation prefers stable fixes."""
    if ecosystem == "pypi":
        return key[2] == (10**9,) and key[4] == (10**9,)
    if ecosystem == "npm":
        return key[3] == (1,)
    return True


def _group(docs: list[dict]) -> list[list[dict]]:
    """Union advisories that alias each other (PYSEC/GHSA/CVE for the same issue)."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for d in docs:
        for alias in d.get("aliases") or []:
            union(d["id"], alias)
        find(d["id"])
    groups: dict[str, list[dict]] = {}
    for d in docs:
        groups.setdefault(find(d["id"]), []).append(d)
    return list(groups.values())


def _primary(group: list[dict]) -> dict:
    def rank(d: dict) -> tuple:
        vid = d["id"]
        return (
            0 if vid.startswith("MAL-") else 1,
            0 if vid.startswith("GHSA-") else (1 if vid.startswith("CVE-") else 2),
            vid,
        )
    return sorted(group, key=rank)[0]


def advisory_findings(comp: Component, docs: list[dict], result: ScanResult | None = None,
                      source: str = "osv") -> list[Finding]:
    findings: list[Finding] = []
    kev_examined = result.examine(sources.KEV.name) if result is not None else None
    withdrawn_mal = [d for d in docs if d.get("withdrawn") and str(d.get("id", "")).startswith("MAL-")]
    for d in withdrawn_mal:
        # a live withdrawal is newer than any bundled snapshot: report it, never drop it (§4.3)
        f = Finding(
            rule_id="ait.pkg.malicious",
            title=f"Known-malicious package version ({comp.name} {comp.version})",
            severity="critical",
            verdict="malicious",
            confidence=98,
            component=comp,
            evidence=[Evidence("osv", d["id"], f"https://osv.dev/vulnerability/{d['id']}",
                               {"summary": d.get("summary"), "aliases": d.get("aliases") or []})],
            remediation=MAL_REMEDIATION,
            advisory_id=d["id"],
            maps_to=[OWASP_SUPPLY_CHAIN],
        )
        f.withdraw(str(d["withdrawn"]))
        findings.append(f)
    for group in _group([d for d in docs if not d.get("withdrawn")]):
        primary = _primary(group)
        all_ids = sorted({d["id"] for d in group} | {a for d in group for a in d.get("aliases") or []})
        cves = [i for i in all_ids if i.startswith("CVE-")]
        evidence = [
            Evidence(
                source,
                d["id"],
                f"https://osv.dev/vulnerability/{d['id']}",
                {"summary": d.get("summary"), "published": d.get("published"), "aliases": d.get("aliases") or []},
            )
            for d in group
        ]
        if primary["id"].startswith("MAL-"):
            findings.append(Finding(
                rule_id="ait.pkg.malicious",
                title=f"Known-malicious package version ({comp.name} {comp.version})",
                severity="critical",
                verdict="malicious",
                confidence=98,
                component=comp,
                evidence=evidence,
                remediation=MAL_REMEDIATION,
                advisory_id=primary["id"],
                maps_to=[OWASP_SUPPLY_CHAIN],
            ))
            continue
        severity, basis = "info", ""
        for d in group:
            sev, why = advisory_severity(d)
            if SEVERITY_RANK[sev] > SEVERITY_RANK[severity]:
                severity, basis = sev, why
        kev_hits = [c for c in cves if kev_entry(c)]
        if kev_examined is not None and cves:
            kev_examined.checked += 1
            if kev_hits:
                kev_examined.with_data += 1
        if kev_hits:
            severity = "critical"
            basis = f"CISA KEV ({', '.join(kev_hits)})"
            for c in kev_hits:
                entry = kev_entry(c) or {}
                evidence.append(Evidence("kev", c, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                                         {"dateAdded": entry.get("dateAdded")}))
        fixed: list[str] = []
        for d in group:
            for f in fixed_versions(d, comp):
                if f not in fixed:
                    fixed.append(f)
        nxt = _next_fix(comp, fixed)
        if nxt:
            remediation = f"Upgrade {comp.name} to {nxt} or later."
        elif fixed:
            remediation = f"Upgrade {comp.name}; fixed in: {', '.join(fixed)}."
        else:
            remediation = "No fixed version published; assess exposure and consider an alternative."
        summary = primary.get("summary") or next((d.get("summary") for d in group if d.get("summary")), None)
        label = cves[0] if cves else primary["id"]
        title = f"{comp.name} {comp.version}: {label}"
        if summary:
            title += f" — {summary}"
        evidence[0].detail["severity_basis"] = basis
        evidence[0].detail["fixed_versions"] = fixed
        findings.append(Finding(
            rule_id="ait.vuln.kev" if kev_hits else "ait.vuln.advisory",
            title=title,
            severity=severity,
            verdict="suspicious" if SEVERITY_RANK[severity] >= SEVERITY_RANK["high"] else "unknown",
            confidence=90 if comp.source in ("lockfile", "bom") else 75,
            component=comp,
            evidence=evidence,
            remediation=remediation,
            advisory_id=primary["id"],
            kev=bool(kev_hits),
            maps_to=[OWASP_SUPPLY_CHAIN],
        ))
    return findings


def judge(
    components: list[Component],
    result: ScanResult,
    client: OSVClient,
    max_vulns: int | None = None,
) -> list[Finding]:
    examined = result.examine(sources.OSV.name)
    if client.offline:
        examined.skipped = "offline (cache only)"
    if not kev_catalog().get("count"):
        result.examine(sources.KEV.name).skipped = "KEV catalog not built (tools/build_kev.py)"
    targets: dict[tuple, list[Component]] = {}
    unversioned = 0
    for comp in components:
        if comp.ctype != "library" or comp.ecosystem not in OSV_ECOSYSTEMS:
            continue
        if not comp.version:
            unversioned += 1
            continue
        q = (OSV_ECOSYSTEMS[comp.ecosystem], comp.name, comp.version)
        targets.setdefault(q, []).append(comp)
    if unversioned:
        result.notes.append(
            f"osv: {unversioned} package(s) without an exact version were not checked "
            "(commit a lockfile to judge them)"
        )
    if not targets:
        return []
    subset_ids: dict[tuple, list[str]] = {}
    subset_docs_: dict[str, dict] = {}
    try:
        ids_by_query = client.query_ids(list(targets))
    except net.NetError as err:
        examined.errors += 1
        result.notes.append(f"osv: query failed ({err}); vulnerability status UNVERIFIED, not safe")
        ids_by_query = {}
        subset_ids, subset_docs_, _ = _judge_from_subset(targets, result, "OSV unreachable")
    else:
        if client.offline:
            uncached = {q: c for q, c in targets.items() if q not in ids_by_query}
            if uncached:
                subset_ids, subset_docs_, _ = _judge_from_subset(uncached, result, "offline")
    examined.checked += len(ids_by_query)
    all_ids = sorted({i for ids in ids_by_query.values() for i in ids})
    docs = client.details(all_ids) if all_ids else {}
    missing = [i for i in all_ids if i not in docs]
    if missing and client.offline:
        # nothing is fetched offline, so nothing failed: say what the cache did not hold
        result.notes.append(f"osv: offline; {len(missing)} advisory detail(s) are not in the cache, so those "
                            "advisories are not shown")
    elif missing:
        examined.errors += len(missing)
        result.notes.append(f"osv: {len(missing)} advisory detail(s) could not be fetched")
    findings: list[Finding] = []
    hidden = 0
    for q, comps in targets.items():
        source, ids, pool = "osv", ids_by_query.get(q), docs
        if ids is None:
            source, ids, pool = "osv-subset", subset_ids.get(q), subset_docs_
        if ids is None:
            continue
        if ids and source == "osv":
            examined.with_data += 1
        for comp in comps:
            per = advisory_findings(comp, [pool[i] for i in ids if i in pool], result, source)
            per.sort(key=lambda f: (-SEVERITY_RANK[f.severity], not f.kev, f.advisory_id or ""))
            if max_vulns is not None:
                keep = [f for f in per if f.rule_id == "ait.pkg.malicious"]
                rest = [f for f in per if f.rule_id != "ait.pkg.malicious"]
                hidden += max(0, len(rest) - max_vulns)
                per = keep + rest[:max_vulns]
            findings.extend(per)
    if hidden:
        result.notes.append(f"osv: {hidden} lower-priority advisory finding(s) hidden by --max-vulns")
    return findings
