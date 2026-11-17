"""Under which terms the wheel may carry an OSV record (design doc 13, H.3).

OSV aggregates databases with different licences; a record's id prefix names its database. The
bundle builders keep only records from the databases listed here, each checked against
https://osv.dev/ "Current data sources" (read 2026-11-17), and write the list into the bundle with
a record count per database, so NOTICE can attribute them. Every other prefix is left out and
counted: unknown ones because nobody checked their terms, and some known ones because their
licence forbids it (Chainguard's CGA- records are CC-BY-NC-ND 4.0; Ubuntu's are CC-BY-SA 4.0,
whose share-alike terms would reach the trimmed copies).

To add a database: read its licence on its own repository, add it to SOURCES, and if its licence
is new, decide whether it belongs in REDISTRIBUTABLE.
"""

from __future__ import annotations

from collections.abc import Iterable

SOURCES = {
    "GHSA": {"source": "GitHub Advisory Database", "licence": "CC-BY-4.0",
             "url": "https://github.com/github/advisory-database"},
    "PYSEC": {"source": "PyPI Advisory Database", "licence": "CC-BY-4.0",
              "url": "https://github.com/pypa/advisory-database"},
    "MAL": {"source": "OpenSSF Malicious Packages", "licence": "Apache-2.0",
            "url": "https://github.com/ossf/malicious-packages"},
}
# Licences whose terms allow a trimmed copy to ship in an Apache-2.0 wheel with attribution.
REDISTRIBUTABLE = frozenset({"CC-BY-4.0", "Apache-2.0", "CC0-1.0"})


def prefix(vid: str) -> str:
    """The database part of an OSV id ("GHSA-xxxx-…" -> "GHSA"); "" when the id has none."""
    head, sep, rest = str(vid or "").partition("-")
    return head if sep and head and rest else ""


def terms(vid: str) -> dict | None:
    """The database and licence a record comes under, or None when it may not be redistributed."""
    p = prefix(vid)
    info = SOURCES.get(p)
    if not info or info["licence"] not in REDISTRIBUTABLE:
        return None
    return {"prefix": p, **info}


def summarise(ids: Iterable[str]) -> tuple[list[dict], dict[str, int]]:
    """(terms with a `records` count per database, sorted by prefix; {prefix: count} left out).
    Each distinct id counts once."""
    kept: dict[str, dict] = {}
    excluded: dict[str, int] = {}
    for vid in set(ids):
        t = terms(vid)
        if t:
            kept.setdefault(t["prefix"], dict(t, records=0))["records"] += 1
        else:
            key = prefix(vid) or "(no prefix)"
            excluded[key] = excluded.get(key, 0) + 1
    return [kept[p] for p in sorted(kept)], dict(sorted(excluded.items()))


def describe_excluded(excluded: dict[str, int]) -> str:
    return ", ".join(f"{p} {n}" for p, n in excluded.items())
