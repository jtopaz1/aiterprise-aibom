"""Third-party AI-BOM / SBOM ingest (C09): judge BOMs produced by cdxgen, Snyk, OWASP, or us.

CycloneDX JSON 1.4–1.7 (nested components, ML-BOM model components) and SPDX 2.x JSON. Files may
carry a UTF-8 BOM or be UTF-16 (PowerShell) — two measured vendors failed on that (G6).
A component without a version cannot be judged; we keep it and say so (Appendix H.2: the same
tree through Snyk's version-less BOM produced no findings).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import purl as purls
from . import taxonomy
from .model import Component, Location
from .textio import read_text, loads_json
from .walk import rel_posix

BOM_FILE_HINTS = (".cdx.json", ".bom.json", ".spdx.json")
BOM_FILE_NAMES = {"bom.json", "sbom.json", "aibom.json", "aibom.cdx.json", "cyclonedx.json"}

_CDX_TYPE = {
    "library": "library",
    "framework": "library",
    "machine-learning-model": "model",
    "data": "dataset",
}
_HASH_ALG = {"SHA-1": "sha1", "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512", "MD5": "md5"}


class BOMError(ValueError):
    pass


def looks_like_bom_file(path: Path) -> bool:
    name = path.name.lower()
    return name in BOM_FILE_NAMES or name.endswith(BOM_FILE_HINTS)


def find_bom_files(files: list[Path]) -> list[Path]:
    return [f for f in files if looks_like_bom_file(f)]


def detect(doc: Any) -> str | None:
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if str(doc.get("spdxVersion", "")).startswith("SPDX-"):
            return "spdx"
    return None


def _licence(entry: dict) -> str | None:
    lics = entry.get("licenses") or []
    names: list[str] = []
    for lic in lics:
        if not isinstance(lic, dict):
            continue
        if lic.get("expression"):
            names.append(str(lic["expression"]))
        inner = lic.get("license") or {}
        name = inner.get("id") or inner.get("name")
        if name and not str(name).startswith("LicenseRef-AIterprise-Verdict"):
            names.append(str(name))
    return " AND ".join(dict.fromkeys(names)) if names else None


def _props(entry: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in entry.get("properties") or []:
        if isinstance(p, dict) and p.get("name"):
            out[str(p["name"])] = str(p.get("value", ""))
    return out


def _cdx_component(entry: dict, rel: str) -> Component | None:
    if not isinstance(entry, dict) or not entry.get("name"):
        return None
    props = _props(entry)
    parsed = purls.parse(entry.get("purl", "")) if entry.get("purl") else None
    ctype = props.get("aiterprise:ctype") or _CDX_TYPE.get(entry.get("type", ""), None)
    if ctype is None:
        ctype = "library" if parsed and parsed.ecosystem not in ("huggingface", "docker", "oci") else (
            "model" if parsed and parsed.ecosystem == "huggingface" else entry.get("type", "library"))
    if parsed is not None and parsed.ecosystem == "huggingface" and ctype == "library":
        ctype = "model"
    ecosystem = parsed.ecosystem if parsed else None
    name = parsed.full_name if parsed else str(entry["name"])
    if parsed is None and entry.get("group"):
        name = f"{entry['group']}/{entry['name']}" if str(entry["group"]).startswith("@") else str(entry["name"])
    version = (parsed.version if parsed else None) or (str(entry["version"]) if entry.get("version") else None)
    comp = Component(
        name=name,
        ctype=ctype,
        version=version,
        ecosystem=ecosystem,
        licence=_licence(entry),
        source="bom",
        locations=[Location(rel)],
    )
    for h in entry.get("hashes") or []:
        alg = _HASH_ALG.get(str(h.get("alg", "")).upper())
        if alg and h.get("content"):
            comp.hashes[alg] = str(h["content"]).lower()
    if entry.get("purl"):
        comp.properties["purl"] = entry["purl"]
    if entry.get("bom-ref"):
        comp.properties["bom_ref"] = entry["bom-ref"]
    kept = {k: v for k, v in props.items() if not k.startswith("aiterprise:finding")}
    if kept:
        comp.properties["bom_properties"] = kept
    if comp.ctype == "library" and ecosystem:
        cat = taxonomy.ai_category(comp.name, ecosystem)
        comp.ai = cat is not None
        if cat:
            comp.properties["ai_category"] = cat
    elif comp.ctype in ("model", "dataset", "model-file", "mcp-server", "agent-skill"):
        comp.ai = True
    if not version and comp.ctype == "library":
        comp.properties["unjudgeable"] = "no version in BOM"
    return comp


def _walk_cdx(entries: list, rel: str, out: list[Component]) -> None:
    for entry in entries or []:
        comp = _cdx_component(entry, rel)
        if comp is not None:
            out.append(comp)
        if isinstance(entry, dict) and entry.get("components"):
            _walk_cdx(entry["components"], rel, out)


def ingest_cyclonedx(doc: dict, rel: str) -> list[Component]:
    out: list[Component] = []
    _walk_cdx(doc.get("components") or [], rel, out)
    return out


def ingest_spdx(doc: dict, rel: str) -> list[Component]:
    out: list[Component] = []
    for pkg in doc.get("packages") or []:
        purl = next(
            (r.get("referenceLocator") for r in pkg.get("externalRefs") or []
             if r.get("referenceType") == "purl"),
            None,
        )
        entry = {
            "name": pkg.get("name"),
            "version": pkg.get("versionInfo"),
            "purl": purl,
            "type": "library",
        }
        comp = _cdx_component(entry, rel)
        if comp is None:
            continue
        lic = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
        if lic and lic not in ("NOASSERTION", "NONE"):
            comp.licence = lic
        for c in pkg.get("checksums") or []:
            alg = str(c.get("algorithm", "")).lower().replace("-", "")
            if alg in ("sha1", "sha256", "sha512", "md5") and c.get("checksumValue"):
                comp.hashes[alg] = str(c["checksumValue"]).lower()
        out.append(comp)
    return out


def ingest_file(path: Path, root: Path | None = None) -> tuple[str, list[Component]]:
    """Returns (format, components). Raises BOMError if the file is not a BOM."""
    rel = rel_posix(path, root) if root else path.name
    try:
        doc = loads_json(read_text(path))
    except ValueError as err:
        raise BOMError(f"{rel}: not valid JSON ({err})") from None
    kind = detect(doc)
    if kind == "cyclonedx":
        return f"CycloneDX {doc.get('specVersion', '?')}", ingest_cyclonedx(doc, rel)
    if kind == "spdx":
        return str(doc.get("spdxVersion")), ingest_spdx(doc, rel)
    raise BOMError(f"{rel}: not a CycloneDX or SPDX JSON document")
