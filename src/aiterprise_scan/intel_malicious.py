"""Known-malicious package versions (C14) from the bundled AIT snapshot of OSV `MAL-` records.

The snapshot (`data/ait/malicious-versions.json.gz`, built by `tools/build_malicious.py`) carries
version sets independently of the registries: a malicious release is often unpublished, and
"not in the registry" is not "safe" (design doc 13, G7). Withdrawn records are dropped at build
time and refused at load time — the 2026-10-27 snapshot once shipped 25 withdrawn records as
CRITICAL findings (Appendix H, v1.14).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from functools import lru_cache

from . import data
from .model import (
    OWASP_SUPPLY_CHAIN,
    Component,
    Evidence,
    Finding,
    ScanResult,
    normalize_name,
)
from .versions import range_contains, versions_equal

SNAPSHOT_FILE = "malicious-versions.json.gz"  # schema ait-malicious-versions/2
LEGACY_SNAPSHOT_FILE = "malicious-versions.json"  # schema /1, read when the v2 file is absent
SOURCE = "ait-malicious"
REMEDIATION = (
    "Remove the package; pin to a release that is not listed as affected; rotate every "
    "credential reachable from any environment where it was installed. Malicious records have "
    "no 'fixed' version."
)


@dataclass(frozen=True)
class MalRecord:
    id: str
    ecosystem: str
    name: str
    versions: tuple[str, ...]
    all_versions: bool
    published: str | None
    summary: str | None
    aliases: tuple[str, ...] = field(default_factory=tuple)

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"


@dataclass
class Snapshot:
    generated_at: str | None
    source: str
    records: Mapping[tuple[str, str], list[MalRecord]]
    refused_withdrawn: int = 0
    inputs: list[dict] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)  # precomputed by the builder (v2)
    by_ecosystem: dict[str, int] = field(default_factory=dict)

    def records_by_ecosystem(self) -> dict[str, int]:
        if self.by_ecosystem:
            return dict(self.by_ecosystem)
        out: dict[str, int] = {}
        for (eco, _name), recs in self.records.items():
            out[eco] = out.get(eco, 0) + len(recs)
        return out

    @property
    def record_count(self) -> int:
        if "record_count" in self.counts:
            return self.counts["record_count"]
        return sum(len(recs) for recs in self.records.values())

    @property
    def version_count(self) -> int:
        if "version_count" in self.counts:
            return self.counts["version_count"]
        return sum(len(r.versions) for recs in self.records.values() for r in recs)

    @property
    def all_versions_count(self) -> int:
        if "all_versions_count" in self.counts:
            return self.counts["all_versions_count"]
        return sum(1 for recs in self.records.values() for r in recs if r.all_versions)


class _LazyIndex(Mapping):
    """(ecosystem, normalized name) -> records, built on first lookup.

    The v2 snapshot holds ~235k records; materialising all of them costs about a second per
    scan, while a scan only ever looks up the packages it found.
    """

    def __init__(self, packages: dict[str, dict[str, list]]) -> None:
        self._raw: dict[tuple[str, str], list[tuple[str, str, list]]] = {}
        for eco, names in packages.items():
            for name, entries in names.items():
                self._raw.setdefault((eco, normalize_name(name, eco)), []).append((eco, name, entries))
        self._built: dict[tuple[str, str], list[MalRecord]] = {}

    def __getitem__(self, key: tuple[str, str]) -> list[MalRecord]:
        built = self._built.get(key)
        if built is None:
            built = [
                MalRecord(
                    id=entry[0],
                    ecosystem=eco,
                    name=name,
                    versions=tuple(entry[3]),
                    all_versions=bool(entry[2]),
                    published=entry[1] or None,
                    summary=None,
                    aliases=tuple(entry[4]) if len(entry) > 4 else (),
                )
                for eco, name, entries in self._raw[key]
                for entry in entries
            ]
            self._built[key] = built
        return built

    def __contains__(self, key: object) -> bool:
        return key in self._raw

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._raw)

    def __len__(self) -> int:
        return len(self._raw)


def _parse_v2(raw: dict) -> Snapshot:
    counts = {k: raw[k] for k in ("record_count", "version_count", "all_versions_count")
              if isinstance(raw.get(k), int)}
    by_eco = {k: v for k, v in (raw.get("by_ecosystem") or {}).items() if isinstance(v, int)}
    return Snapshot(raw.get("generated_at"), raw.get("source", ""), _LazyIndex(raw.get("packages", {})), 0,
                    list(raw.get("inputs", [])), counts, by_eco)


def parse_snapshot(raw: dict) -> Snapshot:
    if "packages" in raw:
        return _parse_v2(raw)
    index: dict[tuple[str, str], list[MalRecord]] = {}
    refused = 0
    for rec in raw.get("records", []):
        if rec.get("withdrawn"):
            refused += 1  # defensive: the builder already drops these
            continue
        eco = rec["ecosystem"]
        name = normalize_name(rec["name"], eco)
        index.setdefault((eco, name), []).append(
            MalRecord(
                id=rec["id"],
                ecosystem=eco,
                name=rec["name"],
                versions=tuple(rec.get("versions") or ()),
                all_versions=bool(rec.get("all_versions")),
                published=rec.get("published"),
                summary=rec.get("summary"),
                aliases=tuple(rec.get("aliases") or ()),
            )
        )
    return Snapshot(raw.get("generated_at"), raw.get("source", ""), index, refused)


@lru_cache(maxsize=1)
def load_snapshot() -> Snapshot:
    name = SNAPSHOT_FILE if data.exists(SNAPSHOT_FILE) else LEGACY_SNAPSHOT_FILE
    return parse_snapshot(data.load(name))


def _finding(comp: Component, rec: MalRecord, snapshot: Snapshot, *, kind: str) -> Finding:
    detail = {
        "affected_versions": list(rec.versions) if rec.versions else "all versions",
        "published": rec.published,
        "snapshot": snapshot.generated_at,
        "aliases": list(rec.aliases),
    }
    if kind == "exact":
        return Finding(
            rule_id="ait.pkg.malicious",
            title=f"Known-malicious package version ({comp.name} {comp.version})",
            severity="critical",
            verdict="malicious",
            confidence=98,
            component=comp,
            evidence=[Evidence(SOURCE, rec.id, rec.url, detail)],
            remediation=REMEDIATION,
            advisory_id=rec.id,
            maps_to=[OWASP_SUPPLY_CHAIN],
        )
    if kind == "all":
        return Finding(
            rule_id="ait.pkg.malicious",
            title=f"Known-malicious package ({comp.name}: every published version)",
            severity="critical",
            verdict="malicious",
            confidence=95,
            component=comp,
            evidence=[Evidence(SOURCE, rec.id, rec.url, detail)],
            remediation=REMEDIATION,
            advisory_id=rec.id,
            maps_to=[OWASP_SUPPLY_CHAIN],
        )
    if kind == "range":
        admitted = [v for v in rec.versions if range_contains(comp.ecosystem, comp.version_spec or "", v)]
        detail = dict(detail, declared_range=comp.version_spec, admitted_versions=admitted)
        return Finding(
            rule_id="ait.pkg.malicious-range",
            title=(
                f"Declared range {comp.name}{_spec(comp.version_spec)} admits known-malicious "
                f"version(s) {', '.join(admitted)}"
            ),
            severity="medium",
            verdict="suspicious",
            confidence=60,
            component=comp,
            evidence=[Evidence(SOURCE, rec.id, rec.url, detail)],
            remediation=(
                "Pin an exact version outside the affected set and commit a lockfile so the "
                "resolved version is reviewable."
            ),
            advisory_id=rec.id,
            maps_to=[OWASP_SUPPLY_CHAIN],
        )
    # version unknown
    return Finding(
        rule_id="ait.pkg.malicious-unpinned",
        title=f"{comp.name} has known-malicious releases and its version here is unknown",
        severity="low",
        verdict="unknown",
        confidence=40,
        component=comp,
        evidence=[Evidence(SOURCE, rec.id, rec.url, detail)],
        remediation="Pin an exact version (lockfile) so it can be checked against the affected set.",
        advisory_id=rec.id,
        maps_to=[OWASP_SUPPLY_CHAIN],
    )


def _spec(spec: str | None) -> str:
    if not spec:
        return ""
    return spec if spec[0] in "<>=!~^" else f" {spec}"


def judge(components: list[Component], result: ScanResult | None = None,
          snapshot: Snapshot | None = None) -> list[Finding]:
    snapshot = snapshot or load_snapshot()
    examined = result.examine(SOURCE) if result is not None else None
    findings: list[Finding] = []
    for comp in components:
        if comp.ctype != "library" or not comp.ecosystem:
            continue
        if examined is not None:
            examined.checked += 1
        recs = snapshot.records.get((comp.ecosystem, normalize_name(comp.name, comp.ecosystem)))
        if not recs:
            continue
        hit = False
        for rec in recs:
            if rec.all_versions:
                findings.append(_finding(comp, rec, snapshot, kind="all"))
                hit = True
            elif comp.version:
                if any(versions_equal(comp.ecosystem, comp.version, v) for v in rec.versions):
                    findings.append(_finding(comp, rec, snapshot, kind="exact"))
                    hit = True
            elif comp.version_spec:
                admitted = [v for v in rec.versions
                            if range_contains(comp.ecosystem, comp.version_spec, v)]
                if admitted:
                    findings.append(_finding(comp, rec, snapshot, kind="range"))
                    hit = True
            else:
                findings.append(_finding(comp, rec, snapshot, kind="unknown"))
                hit = True
        if hit and examined is not None:
            examined.with_data += 1
    return findings
