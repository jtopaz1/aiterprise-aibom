"""Build `src/aiterprise_scan/data/ait/malicious-versions.json.gz` from OSV `MAL-` records.

Sources (pick one or both):
  --zip PATH        an OSV per-ecosystem export, e.g. the file served at
                    https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
                    (download it yourself; this tool never fetches bulk archives)
  --ids MAL-…       fetch individual records from https://api.osv.dev/v1/vulns/<id>

Withdrawn records are kept apart (`withdrawn` below) so a scan reports a match on one as
`withdrawn` instead of dropping it. Existing records are kept unless --replace is given, so a
small `--ids` run can top up a bulk build; a newer copy of a record (e.g. its withdrawal)
replaces the older one.

    python tools/build_malicious.py --zip PyPI-all.zip --zip npm-all.zip --replace
    python tools/build_malicious.py --ids MAL-2026-2144 MAL-2026-2307

Output schema `ait-malicious-versions/2` (gzip, compact JSON, deterministic bytes):

    {"schema": ..., "generated_at": ..., "inputs": [{"file", "sha256", "bytes", "records"}], ...,
     "packages":  {"<ecosystem>": {"<name>": [[id, published-date, all_versions 0|1, [versions], [aliases]?]]}},
     "withdrawn": {"<ecosystem>": {"<name>": [[id, published-date, all_versions 0|1, [versions], [aliases], withdrawn-date]]}}}

`record_count` and the other counts cover active records only. The summary text is not kept:
every OSV MAL summary is "Malicious code in <name>". `terms` names the database and licence of the
records kept (`tools/osv_terms.py`); a record from any other database is left out and counted in
`excluded`, even when an older snapshot carried it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import osv_terms  # noqa: E402  (a sibling tool, not part of the package)

DATA = Path(__file__).resolve().parents[1] / "src" / "aiterprise_scan" / "data" / "ait"
OUT = DATA / "malicious-versions.json.gz"
ECOSYSTEMS = {"PyPI": "pypi", "npm": "npm", "crates.io": "cargo", "Go": "golang",
              "RubyGems": "gem", "Maven": "maven", "NuGet": "nuget"}
MAX_MEMBER_BYTES = 4 * 1024 * 1024
SCHEMA = "ait-malicious-versions/2"


def records_from_osv(doc: dict) -> list[dict]:
    if not str(doc.get("id", "")).startswith("MAL-"):
        return []
    withdrawn = (str(doc.get("withdrawn") or "")[:10]) or None
    out = []
    for aff in doc.get("affected", []):
        pkg = aff.get("package") or {}
        eco = ECOSYSTEMS.get(pkg.get("ecosystem", ""))
        if not eco or not pkg.get("name"):
            continue
        versions = sorted(set(aff.get("versions") or []))
        all_versions = False
        for rng in aff.get("ranges") or []:
            events = rng.get("events") or []
            introduced_zero = any(e.get("introduced") == "0" for e in events)
            bounded = any("fixed" in e or "last_affected" in e or "limit" in e for e in events)
            if introduced_zero and not bounded:
                all_versions = True
        if not versions and not all_versions:
            continue
        out.append({
            "id": doc["id"],
            "ecosystem": eco,
            "name": pkg["name"],
            "versions": versions,
            "all_versions": all_versions,
            "published": (doc.get("published") or "")[:10] or None,
            "aliases": sorted(set(doc.get("aliases") or [])),
            "withdrawn": withdrawn,
        })
    return out


def _canonical(name: str, eco: str) -> str:
    """The scanner's matching key (aiterprise_scan.model.normalize_name)."""
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower() if eco == "npm" else name


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def from_zip(path: Path) -> list[dict]:
    recs: list[dict] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            if not name.endswith(".json") or not Path(name).name.startswith("MAL-"):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                continue
            recs.extend(records_from_osv(json.loads(zf.read(info).decode("utf-8"))))
    return recs


def from_ids(ids: list[str]) -> list[dict]:
    recs: list[dict] = []
    for vid in ids:
        req = urllib.request.Request(f"https://api.osv.dev/v1/vulns/{vid}",
                                     headers={"User-Agent": "aiterprise-scan-build"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        got = records_from_osv(doc)
        if not got:
            print(f"warning: {vid} produced no records (not a MAL- record, or no package)", file=sys.stderr)
        recs.extend(got)
    return recs


def read_existing(path: Path) -> tuple[list[dict], list[dict]]:
    """Records and input provenance from an existing v1 (.json) or v2 (.json.gz) snapshot."""
    raw = path.read_bytes()
    doc = json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)
    if "packages" not in doc:  # v1
        return list(doc.get("records", [])), []
    recs = []
    for section in ("packages", "withdrawn"):
        for eco, names in (doc.get(section) or {}).items():
            for name, entries in names.items():
                for entry in entries:
                    recs.append({"id": entry[0], "ecosystem": eco, "name": name, "published": entry[1] or None,
                                 "all_versions": bool(entry[2]), "versions": list(entry[3]),
                                 "aliases": list(entry[4]) if len(entry) > 4 else [],
                                 "withdrawn": (entry[5] or None) if len(entry) > 5 else None})
    return recs, list(doc.get("inputs", []))


def encode(records: list[dict], inputs: list[dict]) -> bytes:
    terms, excluded = osv_terms.summarise(r["id"] for r in records)
    records = [r for r in records if osv_terms.terms(r["id"]) is not None]
    sections: dict[str, dict[str, dict[str, list]]] = {"packages": {}, "withdrawn": {}}
    for r in sorted(records, key=lambda r: (r["ecosystem"], r["name"].lower(), r["name"], r["id"])):
        entry = [r["id"], r.get("published") or "", 1 if r["all_versions"] else 0, list(r["versions"])]
        if r.get("withdrawn"):
            entry += [list(r.get("aliases") or []), str(r["withdrawn"])[:10]]
        elif r.get("aliases"):
            entry.append(list(r["aliases"]))
        section = sections["withdrawn" if r.get("withdrawn") else "packages"]
        section.setdefault(r["ecosystem"], {}).setdefault(r["name"], []).append(entry)
    active = [r for r in records if not r.get("withdrawn")]
    packages = sections["packages"]
    doc = {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "OSV MAL- records (OpenSSF malicious-packages); withdrawn records kept apart",
        "licence_note": "each record is under its database's licence, listed in `terms`; records from "
                        "other databases are left out and counted in `excluded`",
        "inputs": inputs,
        "terms": terms,
        "excluded": excluded,
        "record_count": len(active),
        "version_count": sum(len(r["versions"]) for r in active),
        "all_versions_count": sum(1 for r in active if r["all_versions"]),
        "withdrawn_count": len(records) - len(active),
        "package_count": len({(eco, _canonical(name, eco)) for eco, names in packages.items() for name in names}),
        "by_ecosystem": {eco: sum(len(v) for v in names.values()) for eco, names in sorted(packages.items())},
        "packages": packages,
        "withdrawn": sections["withdrawn"],
    }
    text = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
    return gzip.compress(text.encode("utf-8"), compresslevel=9, mtime=0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip", action="append", type=Path, default=[])
    ap.add_argument("--ids", nargs="*", default=[])
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--replace", action="store_true", help="drop existing records first")
    args = ap.parse_args(argv)
    if not args.zip and not args.ids:
        ap.error("give --zip and/or --ids")

    existing: list[dict] = []
    inputs: list[dict] = []
    if not args.replace:
        for candidate in (args.out, DATA / "malicious-versions.json"):
            if candidate.exists():
                existing, inputs = read_existing(candidate)
                break
    new: list[dict] = []
    for z in args.zip:
        got = from_zip(z)
        n_withdrawn = sum(1 for r in got if r.get("withdrawn"))
        inputs.append({"source": "OSV bulk export", "ecosystems": sorted({r["ecosystem"] for r in got}),
                       "file": z.name, "sha256": _sha256(z), "bytes": z.stat().st_size,
                       "records": len(got) - n_withdrawn, "withdrawn": n_withdrawn})
        new.extend(got)
    if args.ids:
        got = from_ids(args.ids)
        inputs.append({"api": "https://api.osv.dev/v1/vulns", "ids": list(args.ids), "records": len(got)})
        new.extend(got)

    merged: dict[tuple[str, str, str], dict] = {}
    for rec in existing + new:
        merged[(rec["id"], rec["ecosystem"], rec["name"])] = rec
    records = list(merged.values())
    blob = encode(records, inputs)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(blob)
    legacy = DATA / "malicious-versions.json"
    if args.out == OUT and legacy.exists():
        legacy.unlink()  # superseded by the v2 snapshot
    built = json.loads(gzip.decompress(blob))
    print(f"wrote {args.out}: {built['record_count']} records ({built['withdrawn_count']} withdrawn kept apart), "
          f"{built['version_count']} versions, {len(blob) / 1e6:.2f} MB")
    if built["excluded"]:
        print(f"left out {sum(built['excluded'].values())} records from databases not cleared for "
              f"redistribution: {osv_terms.describe_excluded(built['excluded'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
