"""Package URL parsing (https://github.com/package-url/purl-spec), enough for BOM ingest."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import unquote

# purl type -> our ecosystem name
TYPE_TO_ECOSYSTEM = {
    "pypi": "pypi",
    "npm": "npm",
    "cargo": "cargo",
    "golang": "golang",
    "gem": "gem",
    "maven": "maven",
    "nuget": "nuget",
    "conda": "conda",
    "huggingface": "huggingface",
    "docker": "docker",
    "oci": "oci",
    "github": "github",
    "generic": "generic",
}


@dataclass
class PackageURL:
    type: str
    namespace: str | None
    name: str
    version: str | None
    qualifiers: dict[str, str] = field(default_factory=dict)
    subpath: str | None = None

    @property
    def full_name(self) -> str:
        """Name as the ecosystem spells it (npm `@scope/name`, maven `group:artifact`)."""
        if not self.namespace:
            return self.name
        if self.type == "maven":
            return f"{self.namespace}:{self.name}"
        return f"{self.namespace}/{self.name}"

    @property
    def ecosystem(self) -> str | None:
        return TYPE_TO_ECOSYSTEM.get(self.type)


def parse(purl: str) -> PackageURL | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl[4:].lstrip("/")
    subpath = None
    if "#" in rest:
        rest, subpath = rest.split("#", 1)
        subpath = unquote(subpath.strip("/")) or None
    qualifiers: dict[str, str] = {}
    if "?" in rest:
        rest, q = rest.split("?", 1)
        for pair in q.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k.lower()] = unquote(v)
    if "/" not in rest:
        return None
    ptype, rest = rest.split("/", 1)
    ptype = ptype.lower()
    version = None
    # the version separator is the last '@' that is not the leading scope '@'
    at = rest.rfind("@")
    if at > 0:
        rest, version = rest[:at], unquote(rest[at + 1 :]) or None
    segments = [unquote(s) for s in rest.strip("/").split("/") if s]
    if not segments:
        return None
    name = segments[-1]
    namespace = "/".join(segments[:-1]) or None
    if ptype == "pypi":
        name = name.replace("_", "-").lower()
    return PackageURL(ptype, namespace, name, version, qualifiers, subpath)
