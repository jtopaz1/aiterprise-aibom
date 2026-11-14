"""CycloneDX AI-BOM emission (C05): components + `vulnerabilities[]` + provenance properties.

CycloneDX 1.7 by default, `--cdx-version 1.6` for consumers still on 1.6. Our own output
re-ingests cleanly through `ingest.py` (every non-standard notion rides in `aiterprise:*`
properties, so other tools ignore what they do not understand).
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

from . import TOOL_NAME, __version__
from .model import Component, Finding, ScanResult

SUPPORTED_SPEC_VERSIONS = ("1.6", "1.7")

_CTYPE_TO_CDX = {
    "library": "library",
    "model": "machine-learning-model",
    "model-file": "machine-learning-model",
    "dataset": "data",
    "mcp-server": "application",
    "mcp-config": "file",
    "agent-skill": "application",
    "ai-endpoint": "data",
}
_HASH_TO_CDX = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5"}

# lower-case tag -> SPDX id, for licences CycloneDX may carry as `license.id`
_SPDX_IDS = {
    "apache-2.0": "Apache-2.0",
    "mit": "MIT",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "isc": "ISC",
    "mpl-2.0": "MPL-2.0",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "cc0-1.0": "CC0-1.0",
    "cc-by-4.0": "CC-BY-4.0",
    "cc-by-sa-4.0": "CC-BY-SA-4.0",
    "cc-by-nc-4.0": "CC-BY-NC-4.0",
    "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0",
    "cc-by-nc-nd-4.0": "CC-BY-NC-ND-4.0",
    "odc-by": "ODC-By-1.0",
    "odc-by-1.0": "ODC-By-1.0",
    "cdla-permissive-2.0": "CDLA-Permissive-2.0",
    "unlicense": "Unlicense",
}


def _bom_ref(comp: Component, index: int) -> str:
    return comp.properties.get("bom_ref") or comp.purl or f"aiterprise:{comp.ctype}:{index}:{comp.name}"


def _licences(comp: Component) -> list[dict[str, Any]]:
    if not comp.licence:
        return []
    lic = comp.licence.strip()
    spdx = _SPDX_IDS.get(lic.lower())
    if spdx:
        return [{"license": {"id": spdx}}]
    if lic in _SPDX_IDS.values():
        return [{"license": {"id": lic}}]
    if " AND " in lic or " OR " in lic or " WITH " in lic:
        return [{"expression": lic}]
    return [{"license": {"name": lic}}]


def _properties(comp: Component) -> list[dict[str, str]]:
    props = [{"name": "aiterprise:ctype", "value": comp.ctype}]
    if comp.ai:
        props.append({"name": "aiterprise:ai", "value": "true"})
    if comp.source:
        props.append({"name": "aiterprise:source", "value": comp.source})
    if comp.version_spec:
        props.append({"name": "aiterprise:version_spec", "value": comp.version_spec})
    for loc in comp.locations:
        props.append({"name": "aiterprise:location", "value": str(loc)})
    for key, value in sorted(comp.properties.items()):
        if key in ("purl", "bom_ref", "bom_properties"):
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True, ensure_ascii=False)
        props.append({"name": f"aiterprise:{key}", "value": str(value)})
    return props


def _component(comp: Component, ref: str) -> dict[str, Any]:
    out: dict[str, Any] = {"type": _CTYPE_TO_CDX.get(comp.ctype, "library"), "bom-ref": ref, "name": comp.name}
    if comp.version:
        out["version"] = comp.version
    if comp.purl:
        out["purl"] = comp.purl
    if comp.hashes:
        out["hashes"] = [
            {"alg": _HASH_TO_CDX[alg], "content": value}
            for alg, value in sorted(comp.hashes.items())
            if alg in _HASH_TO_CDX
        ]
    lic = _licences(comp)
    if lic:
        out["licenses"] = lic
    out["properties"] = _properties(comp)
    return out


def _vulnerability(f: Finding, affects_ref: str | None) -> dict[str, Any]:
    vid = f.advisory_id or f.rule_id
    source_url = next((e.url for e in f.evidence if e.url), None)
    source_name = f.evidence[0].source if f.evidence else TOOL_NAME
    v: dict[str, Any] = {
        "bom-ref": f"finding:{f.fingerprint}",
        "id": vid,
        "source": {"name": source_name, **({"url": source_url} if source_url else {})},
        "ratings": [{"source": {"name": TOOL_NAME}, "severity": f.severity, "method": "other"}],
        "description": f.title,
    }
    if f.remediation:
        v["recommendation"] = f.remediation
    if affects_ref:
        v["affects"] = [{"ref": affects_ref}]
    props = [
        {"name": "aiterprise:rule_id", "value": f.rule_id},
        {"name": "aiterprise:fingerprint", "value": f.fingerprint},
        {"name": "aiterprise:verdict", "value": f.verdict},
        {"name": "aiterprise:confidence", "value": str(f.confidence)},
        {"name": "aiterprise:status", "value": f.status},
    ]
    if f.location:
        props.append({"name": "aiterprise:location", "value": str(f.location)})
    if f.kev:
        props.append({"name": "aiterprise:kev", "value": "true"})
    for tag in f.maps_to:
        props.append({"name": "aiterprise:maps_to", "value": tag})
    v["properties"] = props
    return v


def build(result: ScanResult, spec_version: str = "1.7", include_findings: bool = True) -> dict[str, Any]:
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise ValueError(f"unsupported CycloneDX version {spec_version}")
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    refs: dict[int, str] = {}
    refs_by_key: dict[tuple, str] = {}
    components: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for i, comp in enumerate(result.components):
        ref = _bom_ref(comp, i)
        if ref in seen_refs:
            ref = f"{ref}#{i}"
        seen_refs.add(ref)
        refs[id(comp)] = ref
        refs_by_key.setdefault(comp.key(), ref)
        components.append(_component(comp, ref))
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": __version__}]},
            "component": {"type": "application", "bom-ref": "aiterprise:target", "name": result.target},
            "properties": [
                {"name": "aiterprise:mode", "value": result.mode},
                {"name": "aiterprise:components", "value": str(len(result.components))},
            ],
        },
        "components": components,
        "dependencies": [{"ref": "aiterprise:target", "dependsOn": [c["bom-ref"] for c in components]}],
    }
    if include_findings:
        vulns = []
        for f in result.findings:
            ref = None
            if f.component is not None:
                ref = refs.get(id(f.component)) or refs_by_key.get(f.component.key())
            vulns.append(_vulnerability(f, ref))
        if vulns:
            bom["vulnerabilities"] = vulns
    return bom


def dumps(result: ScanResult, spec_version: str = "1.7", include_findings: bool = True) -> str:
    return json.dumps(build(result, spec_version, include_findings), indent=2, ensure_ascii=False) + "\n"
