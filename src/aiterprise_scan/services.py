"""AI endpoints and vector stores as components (design doc 13 §4.2, C02).

AI endpoints — where prompts and data are sent:
- the URL of a known AI provider API in code or configuration (`api.openai.com`,
  `*.openai.azure.com`, `bedrock-runtime.*.amazonaws.com` …);
- an endpoint variable set to a value: `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `OLLAMA_HOST`,
  `AZURE_OPENAI_ENDPOINT` … (`.env`, compose files, Dockerfiles, code defaults);
- a `base_url` / `baseURL` / `api_base` / `azure_endpoint` given to a client in a file that imports
  an AI client library: a self-hosted model or a proxy.

Vector stores — where embeddings, and the text they were made from, are kept:
- a container image (`qdrant/qdrant`, `chromadb/chroma`, `milvusdb/milvus`, `pgvector/pgvector` …);
- a client opened on a literal path, URL or index in code (`chromadb.PersistentClient(path=…)`,
  `QdrantClient(url=…)`, `lancedb.connect(…)`, `FAISS.load_local(…)`, a Pinecone index …);
- a store on disk (`chroma.sqlite3`, `index.faiss`).

What counts is data (`data/ait/ai-assets.json`). Documentation and tests are not read: a README that
mentions an API, or a test that mocks one, is not a use of it. Inventory only; shadow-AI judgement
(C11) is v2. Credentials are never
recorded: user names, passwords, paths, queries and fragments are cut from URLs, and only the
argument that names the store is read, never `api_key` and the like.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import data, taxonomy
from .callargs import line_at, literal_args
from .model import Component, Location
from .textio import TooLarge, read_text
from .walk import is_test_path, rel_posix

MAX_BYTES = 2 * 1024 * 1024
_PY = {".py", ".pyi"}
_JS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
_OTHER_CODE = {".go", ".java", ".kt", ".rb", ".rs", ".cs", ".php", ".ipynb"}
_CONFIG = {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env",
           ".sh", ".bash", ".zsh", ".ps1", ".tf", ".tfvars"}
_YAML = {".yaml", ".yml"}
_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock"}
_URL_RE = re.compile(r"""https?://[^\s"'`<>()\[\]{}\\,;|^]+""")
_HOST_PORT_RE = re.compile(r"^[A-Za-z0-9.-]+:\d{2,5}$")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}
_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
_IPV6_RE = re.compile(r"^[0-9a-f:]+$")
_IMAGE_RE = re.compile(r"""^[ \t]*(?:-[ \t]+)?image:[ \t]*["']?([^\s"'#]+)""", re.M)
_FROM_RE = re.compile(r"^[ \t]*FROM[ \t]+(?:--\S+[ \t]+)*([^\s]+)", re.M | re.I)
_PY_IMPORT_RE = re.compile(r"^[ \t]*(?:from|import)[ \t]+([A-Za-z_][\w.]*)", re.M)
_JS_IMPORT_RE = re.compile(r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"]((?:@[\w.-]+/)?[\w.-]+)""")


@lru_cache(maxsize=1)
def _spec() -> dict[str, Any]:
    return data.load("ai-assets.json")


@lru_cache(maxsize=1)
def _env_re() -> re.Pattern[str]:
    names = "|".join(re.escape(n) for n in _spec()["ai_endpoints"]["env"])
    value = r"""(https?://[^\s"'`,;)}\]]+|[A-Za-z0-9.-]+:\d{2,5}\b)"""
    return re.compile(r"(?<![A-Za-z0-9_])(" + names + r")(?![A-Za-z0-9_])[\"']?\]?[ \t]*(?:[:=,]|\|\||\?\?)[ \t]*"
                      r"[\"'`]?" + value)


@lru_cache(maxsize=1)
def _docker_env_re() -> re.Pattern[str]:
    names = "|".join(re.escape(n) for n in _spec()["ai_endpoints"]["env"])
    return re.compile(r"^[ \t]*ENV[ \t]+(" + names + r")[ \t]+[\"']?([^\s\"']+)", re.M)


@lru_cache(maxsize=2)
def _kwarg_re(lang: str) -> re.Pattern[str]:
    names = "|".join(re.escape(n) for n in _spec()["ai_endpoints"]["client_kwargs"][lang])
    sep = r"=" if lang == "python" else r":"
    return re.compile(r"\b(" + names + r")[ \t]*" + sep + r"[ \t]*(['\"`])([^'\"`\n]+)\2")


@lru_cache(maxsize=1)
def _store_calls() -> list[tuple[re.Pattern[str], dict[str, Any]]]:
    return [(re.compile(c["call"] + r"\s*\("), c) for c in _spec()["vector_stores"]["calls"]]


# --------------------------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------------------------

def origin(url: str) -> tuple[str, str, int | None] | None:
    """(scheme://host[:port], host, port) with credentials, path, query and fragment cut off.
    None for anything that is not a real http(s) host (a placeholder such as `<host>` or `${HOST}`)."""
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not (_HOSTNAME_RE.match(host) or _IPV6_RE.match(host)):
        return None
    shown = f"[{host}]" if ":" in host else host
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{shown}" + (f":{port}" if port and port != default else ""), host, port


def provider(host: str, port: int | None, *, by_port: bool) -> str | None:
    """The AI provider an endpoint host belongs to, from the host table. With `by_port` (the value
    is already known to be an AI endpoint, or the host is this machine) a well-known port also
    names one: 11434 is Ollama's."""
    hosts = _spec()["ai_endpoints"]["hosts"]
    if host in hosts:
        return hosts[host]
    for pattern, name in hosts.items():
        if "*" in pattern and fnmatch.fnmatchcase(host, pattern):
            return name
    if port and (by_port or host in _LOCAL_HOSTS):
        return _spec()["ai_endpoints"]["ports"].get(str(port))
    return None


def _uses_ai_client(text: str, python: bool) -> bool:
    wanted = set(_spec()["ai_endpoints"]["client_categories"])
    if python:
        imports = taxonomy.python_import_map()
        for mod in _PY_IMPORT_RE.findall(text):
            parts = mod.split(".")
            for i in range(len(parts), 0, -1):
                dotted = ".".join(parts[:i])
                if taxonomy.ai_category(imports.get(dotted, dotted), "pypi") in wanted:
                    return True
        return False
    for name in _JS_IMPORT_RE.findall(text):
        if taxonomy.ai_category(name, "npm") in wanted:
            return True
    return False


# --------------------------------------------------------------------------------------------
# Vector stores
# --------------------------------------------------------------------------------------------

def _image(ref: str) -> tuple[str, str | None] | None:
    """(repository without registry, tag) of a container image reference."""
    ref = ref.split("@", 1)[0]
    if "$" in ref:
        return None
    last = ref.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    repo = ref[: len(ref) - len(tag) - 1] if tag else ref
    parts = repo.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    if parts[0] == "library":
        parts = parts[1:]
    return "/".join(parts).lower(), (None if tag in (None, "latest") else tag)


def _store_where(value: str) -> str | None:
    value = value.strip()
    if not value or value == ":memory:":
        return None
    if "://" in value:
        o = origin(value)
        return o[0] if o else None
    return value.rstrip("/\\") or None


# --------------------------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------------------------

@dataclass
class _Found:
    comps: dict[str, Component] = field(default_factory=dict)

    def add(self, ctype: str, name: str, loc: Location, how: str, source: str, version: str | None = None,
            **props: Any) -> None:
        comp = self.comps.get(f"{ctype}\0{name}\0{version}")
        if comp is None:
            comp = Component(name=name, ctype=ctype, version=version, source=source,
                             properties={**props, "found_by": []})
            self.comps[f"{ctype}\0{name}\0{version}"] = comp
        comp.add_location(loc)
        for key, value in props.items():
            comp.properties.setdefault(key, value)
        if how not in comp.properties["found_by"]:
            comp.properties["found_by"] = sorted(comp.properties["found_by"] + [how])

    def endpoint(self, value: str, loc: Location, how: str, source: str, fallback: str | None) -> None:
        o = origin(value)
        if o is None:
            return
        name, host, port = o
        known = provider(host, port, by_port=fallback is not None)
        if known is None and fallback is None:
            return
        self.add("ai-endpoint", name, loc, how, source, provider=known or f"{fallback} (self-hosted or proxy)")


def _is_docker(name: str) -> bool:
    low = name.lower()
    return low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile")


def _scan_file(found: _Found, path: Path, rel: str) -> None:
    name, suffix = path.name, path.suffix.lower()
    docker = _is_docker(name)
    code = suffix in _PY or suffix in _JS or suffix in _OTHER_CODE
    if not (code or docker or suffix in _CONFIG or name.lower().startswith(".env")) or name in _LOCKFILES:
        return
    try:
        text = read_text(path, max_bytes=MAX_BYTES)
    except (OSError, TooLarge):
        return
    env_labels = _spec()["ai_endpoints"]["env"]
    source = "code-ref" if code else "config"
    if "://" in text:
        for m in _URL_RE.finditer(text):
            found.endpoint(m.group(0), Location(rel, line_at(text, m.start())), "url", source, None)
    for m in _env_re().finditer(text):
        found.endpoint(m.group(2), Location(rel, line_at(text, m.start())), f"env {m.group(1)}", source,
                       env_labels[m.group(1)])
    if docker:
        for m in _docker_env_re().finditer(text):
            if "$" not in m.group(2) and ("://" in m.group(2) or _HOST_PORT_RE.match(m.group(2))):
                found.endpoint(m.group(2), Location(rel, line_at(text, m.start())), f"env {m.group(1)}", "config",
                               env_labels[m.group(1)])
    if suffix in _PY or suffix in _JS:
        python = suffix in _PY
        if _uses_ai_client(text, python):
            for m in _kwarg_re("python" if python else "javascript").finditer(text):
                found.endpoint(m.group(3), Location(rel, line_at(text, m.start(3))), "client base_url", "code-ref",
                               "unknown")
        _store_clients(found, text, rel)
    if docker or suffix in _YAML:
        images = _spec()["vector_stores"]["images"]
        for m in (_FROM_RE if docker else _IMAGE_RE).finditer(text):
            parsed = _image(m.group(1))
            if parsed and parsed[0] in images:
                found.add("vector-store", images[parsed[0]], Location(rel, line_at(text, m.start(1))),
                          "container image", "config", version=parsed[1], engine=images[parsed[0]],
                          image=m.group(1))


def _store_clients(found: _Found, text: str, rel: str) -> None:
    lowered = text.lower()
    for pattern, call in _store_calls():
        if call["uses"] not in lowered:
            continue
        for m in pattern.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            if text[line_start:m.start()].lstrip().startswith(("#", "//")):
                continue
            parsed = literal_args(text, m.end())
            if parsed is None:
                continue
            positional, keyword = parsed
            value = next((keyword[k] for k in call["args"] if k in keyword), None)
            if value is None and "position" in call and len(positional) > call["position"]:
                value = positional[call["position"]]
            where = _store_where(value[0]) if value else None
            if where is None:
                continue
            found.add("vector-store", f"{call['engine']}:{where}", Location(rel, line_at(text, value[1])),
                      "client call", "code-ref", engine=call["engine"])


def discover_services(root: Path, files: list[Path]) -> list[Component]:
    root = Path(root)
    found = _Found()
    on_disk = _spec()["vector_stores"]["files"]
    for f in files:
        path = f if f.is_absolute() else root / f
        rel = rel_posix(path, root)
        if is_test_path(rel):
            continue  # mocks and fixtures are not what the application uses
        if path.name in on_disk:
            engine = on_disk[path.name]
            where = rel.rsplit("/", 1)[0] if "/" in rel else "."
            found.add("vector-store", f"{engine}:{where}", Location(rel), "files on disk", "file", engine=engine)
            continue
        _scan_file(found, path, rel)
    return list(found.comps.values())
