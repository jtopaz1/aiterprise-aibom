"""Build `src/aiterprise_scan/data/ait/vuln-subset.json.gz`: OSV advisories for AI packages.

The offline scanner cannot ask OSV, so the wheel carries the advisories for every package in the
AI taxonomy (`data/ait/taxonomy.json`) — design doc 13 §5.3 "bundle carries AI-package CVE subset".
Other packages are reported as not checked when offline.

Input is the OSV per-ecosystem export (download it yourself; this tool never fetches bulk data):

    curl -fLo PyPI-all.zip https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
    curl -fLo npm-all.zip  https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
    python tools/build_vuln_subset.py --zip PyPI-all.zip --zip npm-all.zip

Kept per advisory: id, aliases, summary, published, modified, severity, database_specific.severity
and the `affected` entries for the AI package (ECOSYSTEM/SEMVER ranges; the explicit `versions`
list only when no such range decides). `MAL-` records live in the malicious snapshot and withdrawn
advisories are not active, so neither is kept here. Only advisories from a database whose licence
allows redistribution are kept (`tools/osv_terms.py`); the rest are counted in `excluded`.

Output schema `ait-vuln-subset/1` (gzip, compact JSON, deterministic bytes):

    {"schema", "generated_at", "inputs": [{"file", "sha256", "bytes", "advisories"}],
     "terms": [{"prefix", "source", "licence", "url", "records"}], "excluded": {"<prefix>": count},
     "package_count", "advisory_count",
     "packages": {"<ecosystem>": {"<canonical name>": [<trimmed OSV advisory>, ...]}}}
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import osv_terms  # noqa: E402  (a sibling tool, not part of the package)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "aiterprise_scan" / "data" / "ait"
OUT = DATA / "vuln-subset.json.gz"
SCHEMA = "ait-vuln-subset/1"
ECOSYSTEMS = {"PyPI": "pypi", "npm": "npm"}
MAX_MEMBER_BYTES = 8 * 1024 * 1024
RANGE_TYPES = ("ECOSYSTEM", "SEMVER")


def canonical(name: str, eco: str) -> str:
    """The scanner's matching key (aiterprise_scan.model.normalize_name)."""
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def ai_packages() -> dict[str, set[str]]:
    tax = json.loads((DATA / "taxonomy.json").read_text(encoding="utf-8"))
    return {eco: {canonical(n, eco) for n in names} for eco, names in tax["libraries"].items()}


def trim(doc: dict, wanted: dict[str, set[str]]) -> list[tuple[str, str, dict]]:
    """(ecosystem, canonical name, trimmed advisory) for every AI package the advisory affects."""
    vid = str(doc.get("id", ""))
    if not vid or vid.startswith("MAL-") or doc.get("withdrawn"):
        return []
    if any(str(a).startswith("MAL-") for a in doc.get("aliases") or []):
        return []  # a malicious-release record: the malicious snapshot reports it, with the MAL fingerprint
    out = []
    by_pkg: dict[tuple[str, str], list[dict]] = {}
    for aff in doc.get("affected") or []:
        pkg = aff.get("package") or {}
        eco = ECOSYSTEMS.get(pkg.get("ecosystem", ""))
        if not eco or not pkg.get("name"):
            continue
        name = canonical(pkg["name"], eco)
        if name not in wanted.get(eco, set()):
            continue
        entry: dict = {"package": {"ecosystem": pkg["ecosystem"], "name": pkg["name"]}}
        ranges = [{"type": r["type"], "events": r.get("events") or []}
                  for r in aff.get("ranges") or [] if r.get("type") in RANGE_TYPES]
        if ranges:
            entry["ranges"] = ranges
        elif aff.get("versions"):
            entry["versions"] = sorted(set(aff["versions"]))
        else:
            continue  # nothing we could evaluate offline
        if aff.get("severity"):
            entry["severity"] = aff["severity"]
        by_pkg.setdefault((eco, name), []).append(entry)
    for (eco, name), entries in by_pkg.items():
        slim = {"id": vid, "aliases": sorted(set(doc.get("aliases") or []))}
        for key in ("summary", "published", "modified", "severity"):
            if doc.get(key):
                slim[key] = doc[key]
        sev = (doc.get("database_specific") or {}).get("severity")
        if sev:
            slim["database_specific"] = {"severity": sev}
        slim["affected"] = entries
        out.append((eco, name, slim))
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def from_zip(path: Path, wanted: dict[str, set[str]]) -> tuple[str | None, list[tuple[str, str, dict]]]:
    """(the export's ecosystem, advisories). The ecosystem is the one most records name."""
    got = []
    seen: dict[str, int] = {}
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json") or info.file_size > MAX_MEMBER_BYTES:
                continue
            if Path(info.filename).name.startswith("MAL-"):
                continue
            doc = json.loads(zf.read(info).decode("utf-8"))
            for aff in doc.get("affected") or []:
                eco = ECOSYSTEMS.get((aff.get("package") or {}).get("ecosystem", ""))
                if eco:
                    seen[eco] = seen.get(eco, 0) + 1
            got.extend(trim(doc, wanted))
    return (max(seen, key=seen.get) if seen else None), got


def encode(items: list[tuple[str, str, dict]], inputs: list[dict], covered: dict[str, set[str]]) -> bytes:
    """`covered`: every AI package of each exported ecosystem, kept even with no advisories so an
    offline scan can tell "checked, nothing known" from "outside the subset"."""
    items = [(eco, name, slim) for eco, name, slim in items if eco in covered]
    terms, excluded = osv_terms.summarise(slim["id"] for _, _, slim in items)
    packages: dict[str, dict[str, dict[str, dict]]] = {eco: {n: {} for n in names} for eco, names in covered.items()}
    for eco, name, slim in items:
        if osv_terms.terms(slim["id"]) is None:
            continue  # its database's licence does not allow redistribution, or was never checked
        packages.setdefault(eco, {}).setdefault(name, {})[slim["id"]] = slim  # one copy per id
    ordered = {eco: {name: [docs[i] for i in sorted(docs)] for name, docs in sorted(names.items())}
               for eco, names in sorted(packages.items())}
    doc = {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "OSV advisories for packages in the AI taxonomy, trimmed to the fields the scanner reads",
        "licence_note": "each advisory is under its database's licence, listed in `terms`; advisories from "
                        "other databases are left out and counted in `excluded`",
        "inputs": inputs,
        "terms": terms,
        "excluded": excluded,
        "package_count": sum(len(v) for v in ordered.values()),
        "packages_with_advisories": sum(1 for names in ordered.values() for docs in names.values() if docs),
        "advisory_count": len({d["id"] for names in ordered.values() for docs in names.values() for d in docs}),
        "packages": ordered,
    }
    text = json.dumps(doc, separators=(",", ":"), ensure_ascii=False, sort_keys=False)
    return gzip.compress(text.encode("utf-8"), compresslevel=9, mtime=0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip", action="append", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    wanted = ai_packages()
    items: list[tuple[str, str, dict]] = []
    inputs: list[dict] = []
    covered: dict[str, set[str]] = {}
    for z in args.zip:
        eco, got = from_zip(z, wanted)
        if eco:
            covered[eco] = set(wanted.get(eco, set()))
        inputs.append({"source": "OSV bulk export", "ecosystem": eco, "file": z.name, "sha256": _sha256(z),
                       "bytes": z.stat().st_size, "advisories": len({d["id"] for _, _, d in got})})
        items.extend(got)
    blob = encode(items, inputs, covered)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(blob)
    built = json.loads(gzip.decompress(blob))
    print(f"wrote {args.out}: {built['advisory_count']} advisories; {built['package_count']} AI packages covered, "
          f"{built['packages_with_advisories']} with advisories; {len(blob) / 1e6:.2f} MB")
    if built["excluded"]:
        print(f"left out {sum(built['excluded'].values())} advisories from databases not cleared for "
              f"redistribution: {osv_terms.describe_excluded(built['excluded'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
