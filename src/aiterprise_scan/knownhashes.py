"""Known-bad model hashes (design doc 13 C23, the MVP seed list).

`data/ait/known-bad-hashes.json` lists files that public incident reports name as malicious, by
exact SHA-256 or SHA-1, each with the report it was copied from. The model-file analyzer asks
`lookup` about every model candidate before it sniffs the format: incident payloads are often no
valid model at all (an ELF named `syscore.bin`, a 7z archive named like a PyTorch file).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from . import data

NAME = "known-bad-hashes.json"
ALGORITHMS = ("sha256", "sha1")


@dataclass(frozen=True)
class Index:
    version: str
    by_hash: dict[tuple[str, str], dict[str, Any]]  # (algorithm, lowercase hex) -> entry


@dataclass(frozen=True)
class Match:
    algorithm: str
    digest: str
    entry: dict[str, Any]
    version: str


def build_index(doc: dict[str, Any]) -> Index:
    by_hash: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in doc.get("entries") or []:
        for alg in ALGORITHMS:
            value = entry.get(alg)
            if isinstance(value, str) and value:
                by_hash[(alg, value.lower())] = entry
    return Index(str(doc.get("version") or ""), by_hash)


@lru_cache(maxsize=1)
def _index() -> Index:
    return build_index(data.load(NAME)) if data.exists(NAME) else Index("", {})


def lookup(sha256: str | None, sha1: str | None) -> Match | None:
    """The listed entry for a file with these digests, SHA-256 first; None when it is not listed."""
    index = _index()
    for alg, value in (("sha256", sha256), ("sha1", sha1)):
        if value:
            entry = index.by_hash.get((alg, value.lower()))
            if entry is not None:
                return Match(alg, value.lower(), entry, index.version)
    return None
