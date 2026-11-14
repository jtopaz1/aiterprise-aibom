"""Repository-native package discovery (design doc 13 §4.1-4.2; Appendix H.1 W2 and C01).

`discover_packages` reads manifests and lockfiles:

- PyPI: requirements files (`*requirements*.txt` / `*requirements*.in`, files under a
  `requirements/` directory, pip-compile / `uv pip compile` output), `pyproject.toml` (PEP 621,
  PEP 735 dependency groups, Poetry, uv / PDM dev lists), `Pipfile`, `Pipfile.lock`,
  `poetry.lock`, `uv.lock`.
- conda: `environment.yml` / `environment.yaml` (its nested `pip:` list is PyPI).
- npm: `package.json`, `package-lock.json` / `npm-shrinkwrap.json` (v1, v2, v3),
  `pnpm-lock.yaml` (v5, v6, v9), `yarn.lock` (classic v1 and berry).

Rules (H.1): a lockfile always wins over a manifest in the same directory and ecosystem, and a
range is never reported as an exact version. Scanned files are untrusted: every parser tolerates
malformed input (whatever parsed is kept), `-r` includes never leave the scan root, nothing is
imported or executed.

`discover_imports` finds AI packages used in code (manifest-free discovery, C01): Python `ast`
imports in `.py` files and notebook code cells, and JS/TS `import` / `require` specifiers. Only
packages in the AI taxonomy are reported.
"""

from __future__ import annotations

import ast
import base64
import binascii
import json
import os
import re
import tomllib
import warnings
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, NamedTuple

from . import miniyaml, taxonomy, textio
from .model import Component, Location, normalize_name
from .walk import rel_posix

__all__ = ["discover_packages", "discover_imports"]

MAX_MANIFEST_BYTES = textio.DEFAULT_MAX_BYTES  # 16 MB: larger files are skipped
MAX_SOURCE_BYTES = 2 * 1024 * 1024  # source files / notebooks scanned for imports
MAX_INCLUDE_DEPTH = 10  # nested `-r` includes

LOCK = "lockfile"
MANIFEST = "manifest"

_DEV_TOKENS = frozenset(
    {"dev", "devel", "develop", "development", "test", "tests", "testing", "lint", "linting",
     "doc", "docs", "typing", "ci", "qa"}
)

# conda package names whose PyPI name differs (used only for AI classification).
_CONDA_TO_PYPI = {
    "pytorch": "torch",
    "pytorch-cpu": "torch",
    "pytorch-gpu": "torch",
    "py-xgboost": "xgboost",
    "py-xgboost-cpu": "xgboost",
    "py-xgboost-gpu": "xgboost",
    "faiss": "faiss-cpu",
    "tensorflow-base": "tensorflow",
    "llama.cpp": "llama-cpp-python",
}


# --------------------------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------------------------


def discover_packages(root: Path, files: list[Path]) -> list[Component]:
    """Packages declared by manifests and lockfiles under `root` (lockfile wins)."""
    root = Path(root)
    found: list[_Found] = []
    infos: dict[Path, _FileInfo] = {}
    seen: set[str] = set()
    queue: list[tuple[Path, Callable[[_Ctx, str], None], str, int]] = []
    for path in files:
        handler = _handler_for(Path(path))
        if handler is not None:
            queue.append((Path(path), handler[0], handler[1], 0))
    i = 0
    while i < len(queue):
        path, parser, kind, depth = queue[i]
        i += 1
        key = _canon(path)
        if key in seen:
            continue
        seen.add(key)
        ctx = _run(parser, kind, root, path)
        if ctx is None:
            continue
        found.extend(ctx.found)
        infos[ctx.path] = ctx.info
        if depth < MAX_INCLUDE_DEPTH:
            for inc in ctx.includes:
                queue.append((inc, _parse_requirements, MANIFEST, depth + 1))
    return _finish(_apply_lockfiles(found, infos))


def discover_imports(root: Path, files: list[Path]) -> list[Component]:
    """AI packages imported by Python / notebook / JS / TS sources (version unknown)."""
    root = Path(root)
    imap = taxonomy.python_import_map()
    comps: dict[tuple[str, str], Component] = {}
    for path in files:
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix in _PY_SUFFIXES:
            extract = lambda text: _python_hits(text, imap)  # noqa: E731
        elif suffix == ".ipynb":
            extract = lambda text: _notebook_hits(text, imap)  # noqa: E731
        elif suffix in _JS_SUFFIXES:
            extract = _js_hits
        else:
            continue
        try:
            text = textio.read_text(path, MAX_SOURCE_BYTES)
        except (OSError, textio.TooLarge):
            continue
        try:
            hits = extract(text)
        except Exception:  # hostile / broken source never stops discovery
            continue
        rel = _rel(path, root)
        here: set[tuple[str, str]] = set()
        for eco, dist, imported, line in hits:
            key = (eco, normalize_name(dist, eco))
            if key in here:
                continue  # first import per file is enough evidence
            here.add(key)
            comp = comps.get(key)
            if comp is None:
                comp = Component(name=dist, ctype="library", ecosystem=eco, source="import")
                comp.ai = True
                comp.properties["ai_category"] = taxonomy.ai_category(dist, eco)
                comp.properties["direct"] = True
                comp.properties["import"] = imported
                comps[key] = comp
            comp.add_location(Location(rel, line))
    return sorted(comps.values(), key=_sort_key)


# --------------------------------------------------------------------------------------------
# plumbing
# --------------------------------------------------------------------------------------------


@dataclass
class _Found:
    comp: Component
    kind: str  # LOCK | MANIFEST
    path: Path  # declaring file; its directory is the lockfile-wins scope
    install: str = ""  # npm install name (alias key) or the declared name
    raw_spec: str | None = None  # the declared spec as written (manifests)
    descriptors: frozenset = frozenset()  # yarn (install, name, range) tuples resolving here
    top: bool = False  # npm: installed at the top of a node_modules tree
    dev_known: bool = False  # the lockfile itself states dev-ness for this entry
    prod_seen: bool = False  # merge bookkeeping: a non-dev manifest entry matched


@dataclass
class _FileInfo:
    kind: str
    direct_known: bool = False  # the lockfile records which packages are direct
    workspace: bool = False  # manifest is a workspace root (members declare their own deps)


class _Ctx:
    """What one file declares."""

    def __init__(self, root: Path, path: Path, kind: str) -> None:
        self.root = root
        self.path = path
        self.rel = _rel(path, root)
        self.info = _FileInfo(kind)
        self.found: list[_Found] = []
        self.includes: list[Path] = []

    @property
    def kind(self) -> str:
        return self.info.kind

    def set_kind(self, kind: str) -> None:
        self.info.kind = kind

    def add(
        self,
        name: Any,
        ecosystem: str,
        line: int | None,
        *,
        version: Any = None,
        spec: Any = None,
        raw_spec: str | None = None,
        dev: bool = False,
        direct: bool | None = None,
        hashes: dict[str, str] | None = None,
        install: str = "",
        descriptors: Any = (),
        top: bool = False,
        dev_known: bool = False,
        ai_lookup: tuple[str, str] | None = None,
        **props: Any,
    ) -> Component | None:
        name = _clean(name)
        if not name:
            return None
        version = _clean(version)
        spec = _clean(spec)
        comp = Component(
            name=name,
            ctype="library",
            version=version,
            ecosystem=ecosystem,
            version_spec=None if version else spec,
            locations=[Location(self.rel, line)],
            source=self.kind,
        )
        lookup_name, lookup_eco = ai_lookup or (name, ecosystem)
        category = taxonomy.ai_category(lookup_name, lookup_eco)
        if category:
            comp.ai = True
            comp.properties["ai_category"] = category
        if hashes:
            comp.hashes.update(hashes)
        if dev:
            comp.properties["dev"] = True
        if direct is not None:
            comp.properties["direct"] = direct
        for key, value in props.items():
            if value is None or value is False or value == "" or value == [] or value == {}:
                continue
            comp.properties[key] = value
        self.found.append(
            _Found(comp, self.kind, self.path, install or name, raw_spec, frozenset(descriptors), top, dev_known)
        )
        return comp

    def include(self, target: str) -> None:
        """Queue a `-r` include, resolved relative to this file and confined to the scan root."""
        target = target.strip().strip("\"'")
        if not target or "://" in target or "$" in target:
            return
        try:
            resolved = (self.path.parent / target).resolve()
            if not resolved.is_relative_to(self.root.resolve()) or not resolved.is_file():
                return
        except (OSError, ValueError):
            return
        self.includes.append(resolved)


def _run(parser: Callable[[_Ctx, str], None], kind: str, root: Path, path: Path) -> _Ctx | None:
    try:
        text = textio.read_text(path, MAX_MANIFEST_BYTES)
    except (OSError, textio.TooLarge):
        return None
    ctx = _Ctx(root, path, kind)
    try:
        parser(ctx, text)
    except Exception:  # malformed or hostile input: keep whatever parsed before the error
        pass
    return ctx


def _handler_for(path: Path) -> tuple[Callable[[_Ctx, str], None], str] | None:
    name = path.name.lower()
    fixed = _FIXED_HANDLERS.get(name)
    if fixed is not None:
        return fixed
    if _is_requirements_name(path):
        return _parse_requirements, MANIFEST
    if re.fullmatch(r"environment(?:[-_.][\w.-]*)?\.ya?ml|conda\.ya?ml", name):
        return _parse_environment, MANIFEST
    return None


def _is_requirements_name(path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix not in (".txt", ".in") or name == "manifest.in":
        return False
    if "requirements" in name:
        return True
    return path.parent.name.lower() in ("requirements", "requirements.d", "reqs")


def _is_dev_group(name: str) -> bool:
    return any(tok in _DEV_TOKENS for tok in re.split(r"[-_.\s]+", str(name).lower()))


def _canon(path: Path) -> str:
    try:
        return os.path.normcase(str(path.resolve()))
    except OSError:
        return os.path.normcase(str(path))


def _rel(path: Path, root: Path) -> str:
    rel = rel_posix(path, root)
    if rel == path.as_posix():
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            return rel
    return rel


def _clean(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    return value or None


def _norm(comp: Component) -> str:
    return normalize_name(comp.name, comp.ecosystem)


def _sort_key(comp: Component) -> tuple:
    return (
        comp.ecosystem or "",
        normalize_name(comp.name, comp.ecosystem),
        comp.version or "",
        comp.version_spec or "",
        str(comp.locations[0]) if comp.locations else "",
    )


class _LineIndex:
    """Offset -> 1-based line number in O(log n)."""

    __slots__ = ("starts",)

    def __init__(self, text: str) -> None:
        starts = [0]
        find = text.find
        i = find("\n")
        while i >= 0:
            starts.append(i + 1)
            i = find("\n", i + 1)
        self.starts = starts

    def line(self, offset: int) -> int:
        return bisect_right(self.starts, offset)


_COLON_RE = re.compile(r"\s*:\s*")


def _find_key(text: str, key: str, start: int = 0, want_obj: bool = False) -> int:
    """Offset of the JSON object key `key` (followed by `:` and, if `want_obj`, `{`), or -1."""
    for needle in dict.fromkeys((json.dumps(key, ensure_ascii=False), json.dumps(key))):
        pos = start
        while True:
            idx = text.find(needle, pos)
            if idx < 0:
                break
            m = _COLON_RE.match(text, idx + len(needle))
            if m and (not want_obj or text.startswith("{", m.end())):
                return idx
            pos = idx + 1
    return -1


class _KeyCursor:
    """Finds JSON keys in document order (dicts keep file order), so duplicates resolve right."""

    def __init__(self, text: str, lines: _LineIndex, start: int) -> None:
        self.text, self.lines, self.start, self.pos = text, lines, max(start, 0), max(start, 0)

    def line(self, key: str, want_obj: bool = False) -> int | None:
        idx = _find_key(self.text, key, self.pos, want_obj)
        if idx < 0 and self.pos != self.start:
            idx = _find_key(self.text, key, self.start, want_obj)
        if idx < 0:
            return None
        self.pos = idx + 1
        return self.lines.line(idx)


# --------------------------------------------------------------------------------------------
# lockfile-wins resolution and final merge
# --------------------------------------------------------------------------------------------


def _apply_lockfiles(found: list[_Found], infos: dict[Path, _FileInfo]) -> list[Component]:
    groups: dict[tuple[str, str], list[_Found]] = {}
    dir_keys: dict[Path, str] = {}
    for f in found:
        if f.path not in dir_keys:
            dir_keys[f.path] = _canon(f.path.parent)
        groups.setdefault((dir_keys[f.path], f.comp.ecosystem or ""), []).append(f)
    out: list[Component] = []
    for items in groups.values():
        locks = [f for f in items if f.kind == LOCK]
        manifests = [f for f in items if f.kind == MANIFEST]
        if not locks or not manifests:
            out.extend(f.comp for f in items)
            continue
        index: dict[str, list[_Found]] = {}
        for f in locks:
            index.setdefault(_norm(f.comp), []).append(f)
        for m in manifests:
            candidates = index.get(_norm(m.comp))
            if not candidates:
                out.append(m.comp)  # declared but not locked: keeps its range
                continue
            per_file: dict[Path, list[_Found]] = {}
            for c in candidates:
                per_file.setdefault(c.path, []).append(c)
            # requirements.in pairs with requirements.txt (pip-compile): prefer the same stem
            same_stem = {p: cs for p, cs in per_file.items() if p.stem.lower() == m.path.stem.lower()}
            for cs in (same_stem or per_file).values():
                _merge_manifest(max(cs, key=lambda c: _match_score(c, m)), m)
        workspace = any(infos.get(m.path, _FileInfo(MANIFEST)).workspace for m in manifests)
        if not workspace:
            # A manifest sits next to the lockfile: whatever it does not declare is transitive.
            for f in locks:
                info = infos.get(f.path)
                if info is not None and not info.direct_known:
                    f.comp.properties.setdefault("direct", False)
        out.extend(f.comp for f in locks)
    return out


def _match_score(cand: _Found, man: _Found) -> tuple:
    descriptor = False
    if cand.descriptors and man.raw_spec is not None:
        descriptor = _yarn_desc(f"{man.install}@{man.raw_spec}") in cand.descriptors
    return (
        descriptor,
        cand.comp.properties.get("direct") is True,
        cand.top,
        man.comp.version is not None and cand.comp.version == man.comp.version,
    )


def _merge_manifest(lock: _Found, man: _Found) -> None:
    comp = lock.comp
    for loc in man.comp.locations:
        comp.add_location(loc)
    props = comp.properties
    props["direct"] = True
    if man.raw_spec:
        props.setdefault("declared_spec", man.raw_spec)
    if not lock.dev_known:
        if man.comp.properties.get("dev"):
            if not lock.prod_seen:
                props["dev"] = True
        else:
            lock.prod_seen = True
            props.pop("dev", None)
    if man.comp.version and man.comp.version == comp.version:
        for alg, digest in man.comp.hashes.items():
            comp.hashes.setdefault(alg, digest)
    for key, value in man.comp.properties.items():
        if key not in ("dev", "direct", "ai_category"):
            props.setdefault(key, value)


def _finish(comps: list[Component]) -> list[Component]:
    """Merge identical declarations (same package, version, range and URL) across files."""
    merged: dict[tuple, Component] = {}
    for comp in comps:
        key = (
            comp.ecosystem,
            normalize_name(comp.name, comp.ecosystem),
            comp.version,
            comp.version_spec,
            comp.properties.get("url"),
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = comp
            continue
        for loc in comp.locations:
            existing.add_location(loc)
        for alg, digest in comp.hashes.items():
            existing.hashes.setdefault(alg, digest)
        if comp.source == LOCK:
            existing.source = LOCK
        if not comp.properties.get("dev"):
            existing.properties.pop("dev", None)  # dev only when every declaration is dev
        a, b = existing.properties.get("direct"), comp.properties.get("direct")
        if a is True or b is True:
            existing.properties["direct"] = True
        elif a is False or b is False:
            existing.properties["direct"] = False
        for k, v in comp.properties.items():
            if k not in ("dev", "direct"):
                existing.properties.setdefault(k, v)
    return sorted(merged.values(), key=_sort_key)


# --------------------------------------------------------------------------------------------
# Python: PEP 508 requirement strings
# --------------------------------------------------------------------------------------------


class _Req(NamedTuple):
    name: str
    version: str | None
    spec: str | None
    url: str | None
    extras: list[str]
    markers: str | None
    inferred: bool


_PY_EXACT_RE = re.compile(r"^===?\s*([^\s,;*]+)$")
_PEP508_NAME_RE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$", re.S)
_SCHEME_RE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|(?:git|hg|svn|bzr)\+)")
_LOCAL_RE = re.compile(r"^(?:file:|\.{1,2}(?:[\\/]|$)|[\\/~]|[A-Za-z]:[\\/])")
_ARCHIVE_RE = re.compile(r"\.(?:whl|tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$", re.I)
_SDIST_RE = re.compile(r"^(.+?)-\d[^-]*\.(?:tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$", re.I)
_EGG_RE = re.compile(r"(?:^|&)egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def _py_exact(spec: str | None) -> str | None:
    """The version of an `==X` / `===X` pin; None for every range (including `==1.*`)."""
    if not spec:
        return None
    m = _PY_EXACT_RE.match(spec.strip())
    return m.group(1) if m else None


def _parse_pep508(text: str) -> _Req | None:
    s = text.strip()
    if not s:
        return None
    if _SCHEME_RE.match(s) or _LOCAL_RE.match(s):
        return _parse_bare_ref(s)
    m = _PEP508_NAME_RE.match(s)
    if not m:
        return None
    name, extras_text, rest = m.groups()
    if _ARCHIVE_RE.search(name):
        return None  # a bare local archive such as pkg-1.0-py3-none-any.whl
    extras = [e.strip() for e in (extras_text or "[]")[1:-1].split(",") if e.strip()]
    rest = rest.strip()
    url = markers = spec = None
    if rest.startswith("@"):
        ref = rest[1:].strip()
        mm = re.search(r"\s+;", ref)  # PEP 508: whitespace separates a URL from its markers
        if mm:
            markers = ref[mm.end():].strip() or None
            ref = ref[: mm.start()].strip()
        if not ref or _LOCAL_RE.match(ref):
            return None
        url = ref
    else:
        if ";" in rest:
            rest, markers = rest.split(";", 1)
            markers = markers.strip() or None
        spec = rest.strip()
        if spec.startswith("(") and spec.endswith(")"):
            spec = spec[1:-1].strip()
        if spec and not re.match(r"^[<>=!~]", spec):
            return None  # not a requirement (prose, typo, unsupported syntax)
        spec = re.sub(r"\s+", "", spec) or None
    return _Req(name, _py_exact(spec), spec, url, extras, markers, False)


def _parse_bare_ref(s: str) -> _Req | None:
    """A URL / VCS requirement with no `name @` prefix; local paths are skipped."""
    ref, markers = s, None
    mm = re.search(r"\s+;", s)
    if mm:
        ref, markers = s[: mm.start()].strip(), s[mm.end():].strip() or None
    if _LOCAL_RE.match(ref) or not _SCHEME_RE.match(ref):
        return None
    named = _name_from_url(ref)
    if named is None:
        return None
    name, extras, inferred = named
    return _Req(name, None, None, ref, extras, markers, inferred)


def _name_from_url(ref: str) -> tuple[str, list[str], bool] | None:
    fragment = ref.split("#", 1)[1] if "#" in ref else ""
    m = _EGG_RE.search(fragment)
    if m:
        egg = m.group(1)
        extras: list[str] = []
        em = re.search(r"egg=[^&\[]*\[([^\]]*)\]", fragment)
        if em:
            extras = [e.strip() for e in em.group(1).split(",") if e.strip()]
        return re.sub(r"-\d.*$", "", egg), extras, False
    path = ref.split("#", 1)[0].split("?", 1)[0].rstrip("/")
    last = path.rsplit("/", 1)[-1]
    if last.lower().endswith(".whl"):
        name = last.split("-", 1)[0]
        return (name, [], False) if _VALID_NAME_RE.match(name) else None
    sm = _SDIST_RE.match(last)
    if sm:
        return sm.group(1), [], False
    if re.match(r"^(?:git|hg|svn|bzr)\+", ref) or path.lower().endswith(".git") or "@" in last:
        repo = last.split("@", 1)[0]
        if repo.lower().endswith(".git"):
            repo = repo[:-4]
        if _VALID_NAME_RE.match(repo):
            return repo, [], True  # guessed from the repository name
    return None


_HASH_OPT_RE = re.compile(r"--hash[=\s]\s*([A-Za-z0-9]+):([0-9A-Fa-f]+)")
_OPTION_SPLIT_RE = re.compile(r"\s--?[A-Za-z]")
_COMMENT_RE = re.compile(r"(^|\s+)#.*$")
_INCLUDE_RE = re.compile(r"^(?:--requirement|-r)\s*=?\s*(\S+)")
_COMPILED_RE = re.compile(r"autogenerated by (?:pip-compile|uv)\b", re.I)
_VIA_RE = re.compile(r"^#\s*via\b\s*(.*)$")


def _strip_req_comment(line: str) -> str:
    return _COMMENT_RE.sub("", line)


def _logical_lines(text: str):
    """(first line number, joined line) with backslash continuations folded."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i
        buf = lines[i]
        while buf.endswith("\\") and i + 1 < len(lines):
            i += 1
            buf = buf[:-1] + " " + lines[i]
        yield start + 1, buf
        i += 1


def _add_requirement(ctx: _Ctx, line: str, lineno: int | None, dev: bool, **extra: Any) -> Component | None:
    split = _OPTION_SPLIT_RE.search(line)
    req, opts = (line[: split.start()], line[split.start():]) if split else (line, "")
    parsed = _parse_pep508(req)
    if parsed is None:
        return None
    hashes: dict[str, str] = {}
    for alg, digest in _HASH_OPT_RE.findall(opts):
        hashes.setdefault(alg.lower(), digest.lower())
    return ctx.add(
        parsed.name,
        "pypi",
        lineno,
        version=parsed.version,
        spec=parsed.spec,
        raw_spec=parsed.spec,
        dev=dev,
        direct=True if ctx.kind == MANIFEST else None,
        hashes=hashes,
        dev_known=ctx.kind == LOCK,
        extras=parsed.extras,
        markers=parsed.markers,
        url=parsed.url,
        name_inferred=parsed.inferred,
        **extra,
    )


def _via_is_direct(item: str) -> bool:
    item = item.strip()
    return item.startswith("-r ") or bool(re.search(r"\((?:pyproject\.toml|setup\.py|setup\.cfg)\)$", item))


def _parse_requirements(ctx: _Ctx, text: str) -> None:
    compiled = bool(_COMPILED_RE.search("\n".join(text.splitlines()[:30])))
    if compiled:
        ctx.set_kind(LOCK)  # pip-compile / uv pip compile output is a resolved lock
    dev = _is_dev_group(ctx.path.stem)
    via: dict[int, list[str]] = {}
    last: Component | None = None
    in_via = False
    for lineno, raw in _logical_lines(text):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            indented = raw[:1].isspace()
            m = _VIA_RE.match(stripped)
            if compiled and indented and last is not None and m:
                in_via = True
                if m.group(1).strip():
                    via.setdefault(id(last), []).append(m.group(1).strip())
            elif compiled and indented and last is not None and in_via:
                item = stripped[1:].strip()
                if item:
                    via.setdefault(id(last), []).append(item)
            else:
                in_via = False
            continue
        in_via = False
        line = _strip_req_comment(raw).strip()
        if not line:
            continue
        if line.startswith("-"):
            inc = _INCLUDE_RE.match(line)
            if inc:
                ctx.include(inc.group(1))
            last = None  # -e / --index-url / -c / other options are not packages
            continue
        last = _add_requirement(ctx, line, lineno, dev)
    if compiled:
        for f in ctx.found:
            items = via.get(id(f.comp))
            if items:
                f.comp.properties["direct"] = any(_via_is_direct(x) for x in items)
        ctx.info.direct_known = bool(via)


# --------------------------------------------------------------------------------------------
# Python: TOML manifests and lockfiles
# --------------------------------------------------------------------------------------------

_TOML_HEADER_RE = re.compile(r"^\s*\[{1,2}\s*([^\[\]#]+?)\s*\]{1,2}\s*(?:#.*)?$")


def _toml_parts(s: str) -> tuple[str, ...]:
    parts: list[str] = []
    buf: list[str] = []
    quote = ""
    for ch in s:
        if quote:
            if ch == quote:
                quote = ""
            else:
                buf.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch == ".":
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf).strip())
    return tuple(parts)


class _TomlText:
    """Line lookups for TOML (tomllib keeps no positions)."""

    def __init__(self, text: str) -> None:
        self.lines = text.splitlines()
        self.headers: list[tuple[int, tuple[str, ...]]] = []
        for i, line in enumerate(self.lines):
            m = _TOML_HEADER_RE.match(line)
            if m:
                self.headers.append((i, _toml_parts(m.group(1))))

    def _range(self, parts: tuple[str, ...]) -> tuple[int, int] | None:
        for n, (i, p) in enumerate(self.headers):
            if p == parts:
                end = self.headers[n + 1][0] if n + 1 < len(self.headers) else len(self.lines)
                return i, end
        return None

    def _search(self, sections, pattern: re.Pattern, subtable=None) -> int | None:
        if subtable is not None:
            for i, p in self.headers:
                if p == tuple(subtable):
                    return i + 1
        for parts in sections:
            r = self._range(tuple(parts))
            if r:
                for i in range(r[0] + 1, r[1]):
                    if pattern.search(self.lines[i]):
                        return i + 1
        for i, line in enumerate(self.lines):
            if pattern.search(line):
                return i + 1
        for parts in sections:
            r = self._range(tuple(parts))
            if r:
                return r[0] + 1
        return None

    def find_string(self, sections, value: str) -> int | None:
        return self._search(sections, re.compile(r"([\"'])" + re.escape(value) + r"\1"))

    def find_key(self, sections, key: str, subtable=None) -> int | None:
        return self._search(sections, re.compile(r"^\s*([\"']?)" + re.escape(key) + r"\1\s*="), subtable)


def _toml_array_lines(text: str, table: str = "package") -> list[int]:
    """For each `[[table]]` entry (in order) the line of its `name = ...` key."""
    lines = text.splitlines()
    header = f"[[{table}]]"
    starts = [i for i, line in enumerate(lines) if line.strip() == header]
    out: list[int] = []
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        found = start + 1
        for j in range(start + 1, end):
            stripped = lines[j].lstrip()
            if stripped.startswith("["):
                break
            if re.match(r"^name\s*=", stripped):
                found = j + 1
                break
        out.append(found)
    return out


def _str_list(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _hash_pair(value: Any) -> dict[str, str]:
    if isinstance(value, str) and ":" in value:
        alg, _, digest = value.partition(":")
        if re.fullmatch(r"[0-9A-Fa-f]+", digest.strip()):
            return {alg.strip().lower(): digest.strip().lower()}
    return {}


def _parse_pyproject(ctx: _Ctx, text: str) -> None:
    data = tomllib.loads(text)
    toml = _TomlText(text)
    project = data.get("project")
    if isinstance(project, dict):
        for dep in _str_list(project.get("dependencies")):
            _add_requirement(ctx, dep, toml.find_string([("project",)], dep), dev=False)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for extra, deps in optional.items():
                for dep in _str_list(deps):
                    line = toml.find_string([("project", "optional-dependencies"), ("project",)], dep)
                    _add_requirement(ctx, dep, line, dev=_is_dev_group(extra), optional=True, extra=extra)
    groups = data.get("dependency-groups")  # PEP 735
    if isinstance(groups, dict):
        for group, deps in groups.items():
            for dep in _str_list(deps):  # {include-group = ...} tables are references, skipped
                line = toml.find_string([("dependency-groups",)], dep)
                _add_requirement(ctx, dep, line, dev=_is_dev_group(group), group=group)
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    uv = tool.get("uv")
    if isinstance(uv, dict):
        if isinstance(uv.get("workspace"), dict):
            ctx.info.workspace = True
        for dep in _str_list(uv.get("dev-dependencies")):
            _add_requirement(ctx, dep, toml.find_string([("tool", "uv")], dep), dev=True)
    pdm = tool.get("pdm")
    if isinstance(pdm, dict) and isinstance(pdm.get("dev-dependencies"), dict):
        for group, deps in pdm["dev-dependencies"].items():
            for dep in _str_list(deps):
                line = toml.find_string([("tool", "pdm", "dev-dependencies")], dep)
                _add_requirement(ctx, dep, line, dev=True, group=group)
    poetry = tool.get("poetry")
    if isinstance(poetry, dict):
        _add_poetry_deps(ctx, toml, poetry.get("dependencies"), ("tool", "poetry", "dependencies"), False)
        _add_poetry_deps(ctx, toml, poetry.get("dev-dependencies"), ("tool", "poetry", "dev-dependencies"), True)
        group_tables = poetry.get("group")
        if isinstance(group_tables, dict):
            for group, gdata in group_tables.items():
                if isinstance(gdata, dict):
                    section = ("tool", "poetry", "group", str(group), "dependencies")
                    _add_poetry_deps(ctx, toml, gdata.get("dependencies"), section, _is_dev_group(group), group)


_POETRY_BARE_RE = re.compile(r"^\d+(?:\.\d+)*[0-9A-Za-z.+!-]*$")


def _poetry_exact(spec: str | None) -> str | None:
    """Poetry treats a bare version (`1.2.3`) as an exact pin, like `==1.2.3`."""
    if not spec:
        return None
    exact = _py_exact(spec)
    if exact:
        return exact
    spec = spec.strip()
    return spec if _POETRY_BARE_RE.match(spec) and "*" not in spec else None


def _add_poetry_deps(ctx: _Ctx, toml: _TomlText, table: Any, section: tuple[str, ...], dev: bool,
                     group: str | None = None) -> None:
    if not isinstance(table, dict):
        return
    for name, value in table.items():
        if not isinstance(name, str) or name.lower() == "python":
            continue
        versions: list[str] = []
        extras: list[str] = []
        url = markers = None
        optional = local = False
        for entry in value if isinstance(value, list) else [value]:
            if isinstance(entry, str):
                versions.append(entry.strip())
            elif isinstance(entry, dict):
                if entry.get("path") is not None:
                    local = True
                if isinstance(entry.get("git"), str):
                    url = entry["git"]
                    ref = entry.get("rev") or entry.get("tag") or entry.get("branch")
                    if isinstance(ref, str) and ref:
                        url = f"{url}@{ref}"
                elif isinstance(entry.get("url"), str):
                    url = entry["url"]
                if isinstance(entry.get("version"), str):
                    versions.append(entry["version"].strip())
                extras += [e for e in entry.get("extras") or [] if isinstance(e, str)]
                optional = optional or entry.get("optional") is True
                if isinstance(entry.get("markers"), str):
                    markers = entry["markers"]
        if local and url is None:
            continue  # local path dependency: not a supply-chain package
        versions = [v for v in versions if v]
        spec = versions[0] if len(versions) == 1 else (" || ".join(versions) if versions else None)
        version = _poetry_exact(spec) if len(versions) == 1 else None
        line = toml.find_key([section, section[:-1]], name, subtable=section + (name,))
        ctx.add(name, "pypi", line, version=version, spec=spec, raw_spec=spec, dev=dev, direct=True,
                extras=list(dict.fromkeys(extras)), markers=markers, url=url, optional=optional, group=group)


_PIPFILE_SKIP = frozenset({"source", "requires", "pipenv", "scripts"})


def _pipfile_entry(value: Any) -> tuple[str | None, str | None, list[str], str | None, str | None] | None:
    if isinstance(value, str):
        return value.strip() or "*", None, [], None, None
    if not isinstance(value, dict):
        return None
    url = None
    if isinstance(value.get("git"), str):
        url = value["git"]
        ref = value.get("ref")
        if isinstance(ref, str) and ref:
            url = f"{url}@{ref}"
    elif isinstance(value.get("file"), str):
        url = value["file"]
        if _LOCAL_RE.match(url):
            return None
    elif value.get("path") is not None:
        return None  # local / editable path: the project itself or vendored code
    spec = value.get("version") if isinstance(value.get("version"), str) else (None if url else "*")
    extras = [e for e in value.get("extras") or [] if isinstance(e, str)]
    markers = value.get("markers") if isinstance(value.get("markers"), str) else None
    index = value.get("index") if isinstance(value.get("index"), str) else None
    return spec, url, extras, markers, index


def _parse_pipfile(ctx: _Ctx, text: str) -> None:
    data = tomllib.loads(text)
    toml = _TomlText(text)
    for section, packages in data.items():
        if section in _PIPFILE_SKIP or not isinstance(packages, dict):
            continue
        dev = section == "dev-packages" or _is_dev_group(section)
        for name, value in packages.items():
            parsed = _pipfile_entry(value)
            if parsed is None:
                continue
            spec, url, extras, markers, index = parsed
            line = toml.find_key([(section,)], name, subtable=(section, name))
            ctx.add(name, "pypi", line, version=_py_exact(spec), spec=spec, raw_spec=spec, dev=dev,
                    direct=True, extras=extras, markers=markers, url=url, index=index,
                    category=None if section in ("packages", "dev-packages") else section)


def _parse_pipfile_lock(ctx: _Ctx, text: str) -> None:
    data = textio.loads_json(text)
    if not isinstance(data, dict):
        return
    lines = _LineIndex(text)
    for section, packages in data.items():
        if section.startswith("_") or not isinstance(packages, dict):
            continue
        dev = section == "develop" or _is_dev_group(section)
        cursor = _KeyCursor(text, lines, _find_key(text, section, 0, want_obj=True))
        for name, info in packages.items():
            if not isinstance(info, dict):
                continue
            line = cursor.line(name, want_obj=True)
            url = None
            if isinstance(info.get("git"), str):
                url = info["git"]
                if isinstance(info.get("ref"), str):
                    url = f"{url}@{info['ref']}"
            elif isinstance(info.get("file"), str) and not _LOCAL_RE.match(info["file"]):
                url = info["file"]
            elif info.get("path") is not None or info.get("editable"):
                continue
            spec = info.get("version") if isinstance(info.get("version"), str) else None
            hashes: dict[str, str] = {}
            for h in info.get("hashes") or []:
                for alg, digest in _hash_pair(h).items():
                    hashes.setdefault(alg, digest)
            ctx.add(name, "pypi", line, version=_py_exact(spec), spec=spec, dev=dev, dev_known=True,
                    hashes=hashes, url=url,
                    markers=info.get("markers") if isinstance(info.get("markers"), str) else None)


def _parse_poetry_lock(ctx: _Ctx, text: str) -> None:
    data = tomllib.loads(text)
    packages = data.get("package")
    if not isinstance(packages, list):
        return
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    legacy_files = meta.get("files") if isinstance(meta.get("files"), dict) else {}
    name_lines = _toml_array_lines(text, "package")
    for i, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            continue
        source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
        stype = source.get("type")
        if stype in ("directory", "file"):
            continue  # local path / local archive
        url = index = None
        if stype == "git" and isinstance(source.get("url"), str):
            ref = source.get("resolved_reference") or source.get("reference")
            url = f"{source['url']}@{ref}" if isinstance(ref, str) and ref else source["url"]
        elif stype == "url":
            url = source.get("url")
        elif stype == "legacy":
            index = source.get("url")
        groups = pkg.get("groups")
        dev_known = "category" in pkg or isinstance(groups, list)
        dev = pkg.get("category") == "dev" or (isinstance(groups, list) and bool(groups) and "main" not in groups)
        hashes: dict[str, str] = {}
        files = pkg.get("files") if isinstance(pkg.get("files"), list) else legacy_files.get(pkg.get("name"), [])
        for f in files if isinstance(files, list) else []:
            if isinstance(f, dict):
                for alg, digest in _hash_pair(f.get("hash")).items():
                    hashes.setdefault(alg, digest)
        ctx.add(pkg.get("name"), "pypi", name_lines[i] if i < len(name_lines) else None,
                version=pkg.get("version"), dev=dev, dev_known=dev_known, hashes=hashes, url=url,
                index=index, optional=pkg.get("optional") is True)


def _uv_names(value: Any) -> set[str]:
    out: set[str] = set()
    for dep in value if isinstance(value, list) else []:
        if isinstance(dep, dict) and isinstance(dep.get("name"), str):
            out.add(normalize_name(dep["name"], "pypi"))
    return out


def _reach(graph: dict[str, set[str]], roots: set[str]) -> set[str]:
    seen = set(roots)
    stack = list(roots)
    while stack:
        for nxt in graph.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _parse_uv_lock(ctx: _Ctx, text: str) -> None:
    data = tomllib.loads(text)
    packages = data.get("package")
    if not isinstance(packages, list):
        return
    name_lines = _toml_array_lines(text, "package")
    graph: dict[str, set[str]] = {}
    prod_roots: set[str] = set()
    dev_roots: set[str] = set()
    has_root = False
    for pkg in packages:
        if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
            continue
        edges = graph.setdefault(normalize_name(pkg["name"], "pypi"), set())
        edges |= _uv_names(pkg.get("dependencies"))
        optional = pkg.get("optional-dependencies") if isinstance(pkg.get("optional-dependencies"), dict) else {}
        for deps in optional.values():
            edges |= _uv_names(deps)
        source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
        if "editable" in source or "virtual" in source:  # the project / a workspace member
            has_root = True
            prod_roots |= _uv_names(pkg.get("dependencies"))
            for deps in optional.values():
                prod_roots |= _uv_names(deps)
            dev_groups = pkg.get("dev-dependencies") if isinstance(pkg.get("dev-dependencies"), dict) else {}
            for deps in dev_groups.values():
                dev_roots |= _uv_names(deps)
    prod_reach = _reach(graph, prod_roots)
    dev_reach = _reach(graph, dev_roots)
    ctx.info.direct_known = has_root
    for i, pkg in enumerate(packages):
        if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
            continue
        source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
        if any(k in source for k in ("editable", "virtual", "directory", "path")):
            continue  # the project itself, workspace members and local paths
        norm = normalize_name(pkg["name"], "pypi")
        url = source.get("git") or source.get("url")
        registry = source.get("registry")
        index = registry if isinstance(registry, str) and "pypi.org" not in registry else None
        hashes: dict[str, str] = {}
        sdist = pkg.get("sdist") if isinstance(pkg.get("sdist"), dict) else {}
        hashes.update(_hash_pair(sdist.get("hash")))
        for wheel in pkg.get("wheels") if isinstance(pkg.get("wheels"), list) else []:
            if not hashes and isinstance(wheel, dict):
                hashes.update(_hash_pair(wheel.get("hash")))
        ctx.add(pkg["name"], "pypi", name_lines[i] if i < len(name_lines) else None,
                version=pkg.get("version"),
                direct=(norm in prod_roots or norm in dev_roots) if has_root else None,
                dev=has_root and norm in dev_reach and norm not in prod_reach,
                dev_known=has_root, hashes=hashes, url=url if isinstance(url, str) else None, index=index)


# --------------------------------------------------------------------------------------------
# conda environment files
# --------------------------------------------------------------------------------------------

_CONDA_NAME_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.\-]*)\s*(.*)$")
_CONDA_PLAIN_RE = re.compile(r"^\d[0-9A-Za-z_.+!-]*$")


def _conda_version(rest: str) -> tuple[str | None, str | None, str | None]:
    """(exact version, range, build) from a conda MatchSpec tail.

    conda semantics: `==1.2` and a bare positional `1.2.3` are exact; `=1.2` is fuzzy (1.2.*),
    so it is a range; `=1.2.3=build` (a full pin as `conda env export` writes it) is exact.
    """
    rest = rest.strip()
    if not rest:
        return None, None, None
    if rest.startswith("["):
        vm = re.search(r"version\s*=\s*['\"]?([^'\",\]]+)", rest)
        bm = re.search(r"build\s*=\s*['\"]?([^'\",\]]+)", rest)
        version, spec, _ = _conda_version(vm.group(1)) if vm else (None, None, None)
        return version, spec, bm.group(1).strip() if bm else None
    if rest.startswith("=="):
        v, _, build = rest[2:].strip().partition("=")
        if _CONDA_PLAIN_RE.match(v.strip()):
            return v.strip(), None, build.strip() or None
        return None, rest, None
    if rest.startswith("="):
        v, _, build = rest[1:].partition("=")
        v, build = v.strip(), build.strip()
        if build and build != "*" and _CONDA_PLAIN_RE.match(v):
            return v, None, build
        return None, rest, None
    if rest[0] in "<>!~":
        return None, rest, None
    parts = rest.split()
    if _CONDA_PLAIN_RE.match(parts[0]):
        return parts[0], None, parts[1] if len(parts) > 1 else None
    return None, rest, None


def _add_conda(ctx: _Ctx, item: str, line: int | None, dev: bool) -> None:
    s = item.strip()
    channel = None
    if "::" in s:
        channel, s = (p.strip() for p in s.split("::", 1))
    m = _CONDA_NAME_RE.match(s)
    if not m:
        return
    name, rest = m.group(1), m.group(2).strip()
    version, spec, build = _conda_version(rest)
    pypi = _CONDA_TO_PYPI.get(name.lower(), name)
    ctx.add(name, "conda", line, version=version, spec=spec, raw_spec=rest or None, dev=dev, direct=True,
            ai_lookup=(pypi, "pypi"), channel=channel, build=build,
            pypi_name=pypi if pypi != name else None)


class _SeqFinder:
    """Sequential line lookup for YAML sequence items (`- value`)."""

    _ITEM_RE = re.compile(r"^\s*-\s+(.*?)\s*$")

    def __init__(self, lines: list[str], start: int) -> None:
        self.lines, self.pos = lines, start

    def find(self, value: str) -> int | None:
        want = value.strip()
        for i in range(self.pos, len(self.lines)):
            m = self._ITEM_RE.match(self.lines[i])
            if not m:
                continue
            got = re.sub(r"\s+#.*$", "", m.group(1)).strip()
            if len(got) >= 2 and got[0] == got[-1] and got[0] in "\"'":
                got = got[1:-1]
            if got == want:
                self.pos = i + 1
                return i + 1
        return None

    def skip_to(self, pattern: str) -> None:
        rx = re.compile(pattern)
        for i in range(self.pos, len(self.lines)):
            if rx.match(self.lines[i]):
                self.pos = i + 1
                return


def _parse_environment(ctx: _Ctx, text: str) -> None:
    data = miniyaml.load(text, typed=False)
    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
        return
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if re.match(r"^dependencies\s*:", l)), 0)
    finder = _SeqFinder(lines, start)
    dev = _is_dev_group(ctx.path.stem)
    for item in data["dependencies"]:
        if isinstance(item, str):
            _add_conda(ctx, item, finder.find(item), dev)
        elif isinstance(item, dict) and isinstance(item.get("pip"), list):
            finder.skip_to(r"^\s*-\s+pip\s*:")
            for entry in item["pip"]:
                if not isinstance(entry, str):
                    continue
                line = finder.find(entry)
                spec = _strip_req_comment(entry).strip()
                if spec.startswith("-"):
                    inc = _INCLUDE_RE.match(spec)
                    if inc:
                        ctx.include(inc.group(1))
                    continue
                _add_requirement(ctx, spec, line, dev)


# --------------------------------------------------------------------------------------------
# npm: package.json
# --------------------------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_NPM_EXACT_RE = re.compile(r"^=?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
_NPM_LOCAL_RE = re.compile(r"^(?:file:|link:|workspace:|portal:|exec:|patch:|\.{0,2}/|~/|[A-Za-z]:[\\/])")
_NPM_URL_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|git\+|git@|github:|gitlab:|bitbucket:|gist:)"
    r"|^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.*)?$"
)
_NPM_SECTIONS = (
    ("dependencies", {}),
    ("devDependencies", {"dev": True}),
    ("optionalDependencies", {"optional": True}),
    ("peerDependencies", {"peer": True}),
)


def _parse_npm_spec(install: str, spec: str) -> tuple[str, str | None, str | None, str | None] | None:
    """(package name, exact version, range, url) for a package.json value; None for local refs."""
    s = spec.strip()
    name = install
    if s.startswith("npm:"):  # alias: "my-openai": "npm:openai@^4"
        inner = s[4:]
        at = inner.find("@", 1)
        name, s = (inner[:at], inner[at + 1:]) if at > 0 else (inner, "")
        if not name:
            return None
    if _NPM_LOCAL_RE.match(s):
        return None
    if _NPM_URL_RE.match(s):
        return name, None, None, s
    m = _NPM_EXACT_RE.match(s)
    if m:
        return name, m.group(1), None, None
    return name, None, s or "*", None


def _parse_package_json(ctx: _Ctx, text: str) -> None:
    data = textio.loads_json(text)
    if not isinstance(data, dict):
        return
    if data.get("workspaces"):
        ctx.info.workspace = True
    lines = _LineIndex(text)
    for section, flags in _NPM_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        cursor = _KeyCursor(text, lines, _find_key(text, section, 0, want_obj=True))
        for install, spec in deps.items():
            if not isinstance(spec, str):
                continue
            line = cursor.line(install)
            parsed = _parse_npm_spec(install, spec)
            if parsed is None:
                continue
            name, version, rng, url = parsed
            ctx.add(name, "npm", line, version=version, spec=rng, raw_spec=spec.strip(), install=install,
                    direct=True, dev=bool(flags.get("dev")), optional=bool(flags.get("optional")),
                    peer=bool(flags.get("peer")), url=url, alias=install if install != name else None)


# --------------------------------------------------------------------------------------------
# npm: lockfiles
# --------------------------------------------------------------------------------------------


def _sri_hashes(integrity: Any) -> dict[str, str]:
    """Subresource-integrity strings (`sha512-<base64>`) -> {alg: hex}."""
    out: dict[str, str] = {}
    if not isinstance(integrity, str):
        return out
    for token in integrity.split():
        alg, _, b64 = token.partition("-")
        alg = alg.lower()
        if alg not in ("sha1", "sha256", "sha384", "sha512") or not b64:
            continue
        try:
            raw = base64.b64decode(b64.split("?", 1)[0], validate=True)
        except (binascii.Error, ValueError):
            continue
        out.setdefault(alg, raw.hex())
    return out


_GIT_REF_RE = re.compile(r"^(?:git\+|git:|git@|github:|gitlab:|bitbucket:)")


def _parse_package_lock(ctx: _Ctx, text: str) -> None:
    data = textio.loads_json(text)
    if not isinstance(data, dict):
        return
    lines = _LineIndex(text)
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        _npm_lock_packages(ctx, text, lines, packages)
    elif isinstance(data.get("dependencies"), dict):
        cursor = _KeyCursor(text, lines, _find_key(text, "dependencies", 0, want_obj=True))
        _npm_lock_v1(ctx, data["dependencies"], cursor, 0)


def _npm_lock_packages(ctx: _Ctx, text: str, lines: _LineIndex, packages: dict) -> None:
    """lockfileVersion 2/3: `packages` keyed by install path."""
    direct: dict[str, set[str]] = {}  # project / workspace path -> names it declares
    for key, info in packages.items():
        if isinstance(info, dict) and "node_modules" not in key.split("/"):
            names: set[str] = set()
            for section, _ in _NPM_SECTIONS:
                if isinstance(info.get(section), dict):
                    names.update(info[section])
            direct[key] = names
    ctx.info.direct_known = "" in direct
    hoisted = set().union(*direct.values()) if direct else set()
    cursor = _KeyCursor(text, lines, _find_key(text, "packages", 0, want_obj=True))
    for key, info in packages.items():
        if not isinstance(info, dict):
            continue
        idx = key.rfind("node_modules/")
        if idx < 0:
            continue  # the root project ("") or a workspace package
        install = key[idx + len("node_modules/"):]
        prefix = key[:idx].rstrip("/")
        if not install or info.get("link"):
            continue  # workspace symlink
        resolved = info.get("resolved") if isinstance(info.get("resolved"), str) else ""
        if resolved.startswith("file:"):
            continue
        line = cursor.line(key, want_obj=True)
        name = info.get("name") if isinstance(info.get("name"), str) else install
        if prefix == "":
            top, is_direct = True, install in hoisted
        elif prefix in direct:
            top, is_direct = True, install in direct[prefix]
        else:
            top, is_direct = False, False
        ctx.add(name, "npm", line, version=info.get("version"), dev=info.get("dev") is True,
                direct=is_direct if ctx.info.direct_known else None, hashes=_sri_hashes(info.get("integrity")),
                install=install, top=top, dev_known=True,
                integrity=info.get("integrity") if isinstance(info.get("integrity"), str) else None,
                url=resolved if _GIT_REF_RE.match(resolved) else None,
                optional=info.get("optional") is True, peer=info.get("peer") is True,
                bundled=info.get("inBundle") is True, alias=install if install != name else None)


def _npm_lock_v1(ctx: _Ctx, deps: dict, cursor: _KeyCursor, depth: int) -> None:
    """lockfileVersion 1: nested `dependencies`, walked in document order."""
    for install, info in deps.items():
        if not isinstance(info, dict):
            continue
        line = cursor.line(install, want_obj=True)
        version = info.get("version") if isinstance(info.get("version"), str) else None
        name, url, skip = install, None, False
        if version and version.startswith("npm:"):
            inner = version[4:]
            at = inner.find("@", 1)
            if at > 0:
                name, version = inner[:at], inner[at + 1:]
        if version and _NPM_LOCAL_RE.match(version):
            skip = True
        elif version and not _SEMVER_RE.match(version):
            url, version = version, None
        if not skip:
            ctx.add(name, "npm", line, version=version, dev=info.get("dev") is True,
                    hashes=_sri_hashes(info.get("integrity")), install=install, top=depth == 0, dev_known=True,
                    integrity=info.get("integrity") if isinstance(info.get("integrity"), str) else None,
                    url=url, optional=info.get("optional") is True, bundled=info.get("bundled") is True,
                    alias=install if install != name else None)
        nested = info.get("dependencies")
        if isinstance(nested, dict) and depth < 64:
            _npm_lock_v1(ctx, nested, cursor, depth + 1)


_YAML_KEY_RE = re.compile(r"""^(\s*)(['"]?)(.+?)\2:(?:\s|$)""")


def _yaml_key_lines(text: str, section: str | None = None) -> dict[str, int]:
    """Mapping key -> first line: top-level keys, or every key inside top-level `section`."""
    out: dict[str, int] = {}
    active = section is None
    for i, line in enumerate(text.splitlines()):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        top = not line[0].isspace()
        m = _YAML_KEY_RE.match(line)
        if section is not None:
            if top:
                active = bool(m) and m.group(3) == section
                continue
            if active and m:
                out.setdefault(m.group(3), i + 1)
        elif top and m:
            out.setdefault(m.group(3), i + 1)
    return out


def _strip_peers(version: str) -> str:
    """pnpm peer suffixes: `1.0.0(react@18.2.0)` (v6+) and `1.0.0_react@18.2.0` (v5)."""
    v = version.split("(", 1)[0]
    m = re.match(r"^(\d+\.\d+\.\d+[^_]*)_", v)
    return m.group(1) if m else v


def _pnpm_major(value: Any) -> int:
    try:
        return int(float(str(value).strip("'\" ")))
    except (TypeError, ValueError):
        return 0


def _pnpm_key(key: str, major: int) -> tuple[str | None, str | None]:
    """(name, version) from a pnpm `packages` key: `/a/1.0.0` (v5), `/a@1.0.0` (v6), `a@1.0.0` (v9)."""
    k = key.strip().strip("'\"")
    if k.startswith("/"):
        k = k[1:]
    k = k.split("(", 1)[0]
    slash_form = (0 < major < 6) or (major == 0 and re.match(r"^(?:@[^/@]+/)?[^/@]+/\d", k) is not None)
    if slash_form:
        parts = k.split("/")
        if k.startswith("@"):
            if len(parts) < 3:
                return None, None
            return f"{parts[0]}/{parts[1]}", _strip_peers(parts[2])
        if len(parts) < 2:
            return None, None
        return parts[0], _strip_peers(parts[1])
    at = k.find("@", 1)
    if at <= 0:
        return (k or None), None
    return k[:at], _strip_peers(k[at + 1:])


def _pnpm_ref(name: str, value: Any, major: int) -> tuple[str, str] | None:
    """(name, version) an importer entry resolves to; aliases resolve to the real package."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or v.startswith(("link:", "file:", "workspace:")):
        return None
    if v.startswith("/") or (not v[:1].isdigit() and "@" in v[1:]):
        real, version = _pnpm_key(v, major)
        return (real, version) if real and version else None
    return name, _strip_peers(v)


def _parse_pnpm_lock(ctx: _Ctx, text: str) -> None:
    data = miniyaml.load(text, typed=False)
    if not isinstance(data, dict):
        return
    major = _pnpm_major(data.get("lockfileVersion"))
    importers = data.get("importers")
    if not isinstance(importers, dict):
        single = {k: data[k] for k in ("dependencies", "devDependencies", "optionalDependencies")
                  if isinstance(data.get(k), dict)}
        importers = {".": single} if single else {}
    prod: set[tuple[str, str]] = set()
    dev: set[tuple[str, str]] = set()
    for importer in importers.values():
        if not isinstance(importer, dict):
            continue
        for section in ("dependencies", "optionalDependencies", "devDependencies"):
            deps = importer.get(section)
            if not isinstance(deps, dict):
                continue
            for name, value in deps.items():
                ref = _pnpm_ref(name, value.get("version") if isinstance(value, dict) else value, major)
                if ref:
                    (dev if section == "devDependencies" else prod).add(ref)
    ctx.info.direct_known = bool(importers)
    entries = data.get("packages")
    if not isinstance(entries, dict) or not entries:
        entries = data.get("snapshots") if isinstance(data.get("snapshots"), dict) else {}
        key_lines = _yaml_key_lines(text, "snapshots")
    else:
        key_lines = _yaml_key_lines(text, "packages")
    for key, info in entries.items():
        info = info if isinstance(info, dict) else {}
        name, version = _pnpm_key(str(key), major)
        if isinstance(info.get("name"), str):
            name = info["name"]
        if isinstance(info.get("version"), str):
            version = info["version"]
        if not name:
            continue
        url = None
        resolution = info.get("resolution") if isinstance(info.get("resolution"), dict) else {}
        if version and not _SEMVER_RE.match(version):
            if _NPM_LOCAL_RE.match(version):
                continue
            url, version = version, None
        if resolution.get("type") == "git" and isinstance(resolution.get("repo"), str):
            commit = resolution.get("commit")
            url = f"{resolution['repo']}#{commit}" if isinstance(commit, str) else resolution["repo"]
        if isinstance(resolution.get("directory"), str):
            continue  # local directory dependency
        is_dev = info.get("dev")
        dev_known = isinstance(is_dev, bool)
        ref = (name, version or "")
        is_direct = (ref in prod or ref in dev) if ctx.info.direct_known else None
        if not dev_known and is_direct:
            is_dev, dev_known = ref in dev and ref not in prod, True
        integrity = resolution.get("integrity") if isinstance(resolution.get("integrity"), str) else None
        ctx.add(name, "npm", key_lines.get(str(key).strip()), version=version, dev=bool(is_dev),
                direct=is_direct, hashes=_sri_hashes(integrity), integrity=integrity, url=url,
                top=bool(is_direct), dev_known=dev_known, optional=info.get("optional") is True)


def _yarn_split(header: str) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    quote = False
    for ch in header:
        if ch == '"':
            quote = not quote
            continue
        if ch == "," and not quote:
            out.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    out.append("".join(buf).strip())
    return [d for d in out if d]


def _yarn_desc(descriptor: str) -> tuple[str, str, str] | None:
    """`install@range` -> (install name, real package name, range without `npm:`)."""
    d = descriptor.strip().strip('"')
    if not d:
        return None
    at = d.find("@", 1)
    if at <= 0:
        return d, d, ""
    install, rng = d[:at], d[at + 1:].strip()
    name = install
    if rng.startswith("npm:"):
        inner = rng[4:]
        at2 = inner.find("@", 1)
        if at2 > 0:
            name, rng = inner[:at2], inner[at2 + 1:]
        elif inner.startswith("@"):
            name, rng = inner, ""
        else:
            rng = inner
    return install, name, rng


def _parse_yarn_lock(ctx: _Ctx, text: str) -> None:
    if re.search(r"^__metadata:", text, re.M):
        _parse_yarn_berry(ctx, text)
        return
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for i, raw in enumerate(text.splitlines()):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            current = None
            head = raw.rstrip()
            if head.endswith(":"):
                current = {"descs": _yarn_split(head[:-1]), "line": i + 1, "fields": {}}
                entries.append(current)
            continue
        if current is None or len(raw) - len(raw.lstrip(" ")) != 2:
            continue
        body = raw.strip()
        if body.endswith(":"):
            continue  # nested block (dependencies:)
        key, _, value = body.partition(" ")
        current["fields"][key.strip('"')] = value.strip().strip('"')
    for entry in entries:
        descs = [d for d in (_yarn_desc(x) for x in entry["descs"]) if d]
        if not descs:
            continue
        _, name, rng = descs[0]
        if _NPM_LOCAL_RE.match(rng):
            continue
        fields = entry["fields"]
        integrity = fields.get("integrity")
        ctx.add(name, "npm", entry["line"], version=fields.get("version"), descriptors=descs,
                install=descs[0][0], hashes=_sri_hashes(integrity), integrity=integrity,
                url=rng if _NPM_URL_RE.match(rng) else None,
                alias=descs[0][0] if descs[0][0] != name else None)


def _parse_yarn_berry(ctx: _Ctx, text: str) -> None:
    data = miniyaml.load(text, typed=False)
    if not isinstance(data, dict):
        return
    key_lines = _yaml_key_lines(text)
    for key, info in data.items():
        if key == "__metadata" or not isinstance(info, dict):
            continue
        if info.get("linkType") == "soft":
            continue  # workspace / link / portal
        descs = [d for d in (_yarn_desc(x) for x in _yarn_split(str(key))) if d]
        resolution = info.get("resolution") if isinstance(info.get("resolution"), str) else ""
        name, proto = None, ""
        at = resolution.find("@", 1)
        if at > 0:
            name, proto = resolution[:at], resolution[at + 1:]
        if not name and descs:
            name = descs[0][1]
        if not name or proto.startswith(("workspace:", "link:", "portal:", "file:")):
            continue
        url = proto if proto and not proto.startswith(("npm:", "patch:")) else None
        checksum = info.get("checksum") if isinstance(info.get("checksum"), str) else None
        ctx.add(name, "npm", key_lines.get(str(key)), version=info.get("version"), descriptors=descs,
                install=descs[0][0] if descs else name, url=url, patched=proto.startswith("patch:"),
                yarn_checksum=checksum)


_FIXED_HANDLERS: dict[str, tuple[Callable[[_Ctx, str], None], str]] = {
    "package.json": (_parse_package_json, MANIFEST),
    "package-lock.json": (_parse_package_lock, LOCK),
    "npm-shrinkwrap.json": (_parse_package_lock, LOCK),
    "pnpm-lock.yaml": (_parse_pnpm_lock, LOCK),
    "yarn.lock": (_parse_yarn_lock, LOCK),
    "pyproject.toml": (_parse_pyproject, MANIFEST),
    "pipfile": (_parse_pipfile, MANIFEST),
    "pipfile.lock": (_parse_pipfile_lock, LOCK),
    "poetry.lock": (_parse_poetry_lock, LOCK),
    "uv.lock": (_parse_uv_lock, LOCK),
}


# --------------------------------------------------------------------------------------------
# discover_imports
# --------------------------------------------------------------------------------------------

_PY_SUFFIXES = frozenset({".py", ".pyw"})
_JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"})

_PY_IMPORT_RE = re.compile(r"^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*)", re.M)
_PY_FROM_RE = re.compile(r"^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import[ \t]+\(?[ \t]*([\w \t,]*)", re.M)


def _python_imports(source: str) -> list[tuple[str, int]]:
    """(dotted module, line) for absolute imports; `from a import b` also yields `a.b`."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # SyntaxWarning on odd escapes must never print
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _python_imports_regex(source)
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue  # relative import: local code
            for alias in node.names:
                found.append((node.module if alias.name == "*" else f"{node.module}.{alias.name}", node.lineno))
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            fname = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            arg = node.args[0]
            if fname in ("import_module", "__import__") and isinstance(arg, ast.Constant) \
                    and isinstance(arg.value, str) and not arg.value.startswith("."):
                found.append((arg.value, node.lineno))
    found.sort(key=lambda t: t[1])
    return found


def _python_imports_regex(source: str) -> list[tuple[str, int]]:
    lines = _LineIndex(source)
    found: list[tuple[str, int]] = []
    for m in _PY_IMPORT_RE.finditer(source):
        line = lines.line(m.start(1))
        for part in m.group(1).split(","):
            mod = part.strip().split()[0] if part.strip() else ""
            if mod:
                found.append((mod, line))
    for m in _PY_FROM_RE.finditer(source):
        line = lines.line(m.start(1))
        module = m.group(1)
        names = [n.strip().split()[0] for n in m.group(2).split(",") if n.strip()]
        found.append((module, line))
        found.extend((f"{module}.{n}", line) for n in names if n != "*")
    found.sort(key=lambda t: t[1])
    return found


def _map_python_import(dotted: str, imap: dict[str, str]) -> tuple[str, str] | None:
    """(PyPI distribution, matched import name) via the longest dotted prefix in the map."""
    parts = dotted.split(".")
    for n in range(len(parts), 0, -1):
        key = ".".join(parts[:n])
        dist = imap.get(key)
        if dist and taxonomy.is_ai_package(dist, "pypi"):
            return dist, key
    if parts[0] and taxonomy.is_ai_package(parts[0], "pypi"):
        return normalize_name(parts[0], "pypi"), parts[0]
    return None


def _python_hits(source: str, imap: dict[str, str]) -> list[tuple[str, str, str, int | None]]:
    out = []
    for dotted, line in _python_imports(source):
        hit = _map_python_import(dotted, imap)
        if hit:
            out.append(("pypi", hit[0], hit[1], line))
    return out


def _is_magic(line: str) -> bool:
    s = line.lstrip()
    return s.startswith(("%", "!", "?")) or (s.endswith("?") and not s.startswith("#"))


def _notebook_hits(text: str, imap: dict[str, str]) -> list[tuple[str, str, str, int | None]]:
    nb = textio.loads_json(text)
    if not isinstance(nb, dict):
        return []
    cells = nb.get("cells")
    if not isinstance(cells, list):  # nbformat 3
        cells = [c for ws in nb.get("worksheets") or [] if isinstance(ws, dict)
                 for c in ws.get("cells") or []]
    lines = _LineIndex(text)
    pos = 0
    out = []
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        src = cell.get("source", cell.get("input", ""))
        if isinstance(src, list):
            src = "".join(s for s in src if isinstance(s, str))
        if not isinstance(src, str):
            continue
        src_lines = src.replace("\r\n", "\n").split("\n")
        cleaned = "\n".join("" if _is_magic(l) else l for l in src_lines)
        for dotted, ln in _python_imports(cleaned):
            hit = _map_python_import(dotted, imap)
            if not hit:
                continue
            file_line = None
            raw = src_lines[ln - 1] if 0 < ln <= len(src_lines) else ""
            for needle in dict.fromkeys((json.dumps(raw, ensure_ascii=False)[1:-1], json.dumps(raw)[1:-1])):
                if not needle.strip():
                    continue
                idx = text.find(needle, pos)
                if idx >= 0:
                    pos = idx + len(needle)
                else:
                    idx = text.find(needle)
                if idx >= 0:
                    file_line = lines.line(idx)
                    break
            out.append(("pypi", hit[0], hit[1], file_line))
    return out


_JS_RES = (
    re.compile(r"""(?<![\w$.])(?:import|export)\s+[^'"`;]*?\bfrom\s*(['"])([^'"\n]+)\1"""),
    re.compile(r"""(?<![\w$.])import\s*(['"])([^'"\n]+)\1"""),
    re.compile(r"""(?<![\w$.])import\s*\(\s*(['"`])([^'"`\n]+)\1"""),
    re.compile(r"""(?<![\w$.])require\s*\(\s*(['"`])([^'"`\n]+)\1\s*\)"""),
)


def _js_package(spec: str) -> str | None:
    """npm package name of an import specifier (`@scope/pkg/sub` -> `@scope/pkg`)."""
    s = spec.strip()
    if not s or s.startswith((".", "/", "#", "~", "node:", "data:", "bun:", "jsr:", "virtual:")) \
            or "://" in s or "${" in s:
        return None
    if s.startswith("npm:"):
        s = s[4:]
        if s.startswith("@"):
            parts = s.split("/")
            return f"{parts[0]}/{parts[1].split('@', 1)[0]}" if len(parts) > 1 and parts[1] else None
        return s.split("/", 1)[0].split("@", 1)[0] or None
    if s.startswith("@"):
        parts = s.split("/")
        return f"{parts[0]}/{parts[1]}" if len(parts) > 1 and parts[1] else None
    return s.split("/", 1)[0] or None


def _js_hits(text: str) -> list[tuple[str, str, str, int | None]]:
    lines = _LineIndex(text)
    found: list[tuple[int, str, str]] = []
    for rx in _JS_RES:
        for m in rx.finditer(text):
            name = _js_package(m.group(2))
            if name and taxonomy.is_ai_package(name, "npm"):
                found.append((m.start(2), name, m.group(2)))
    found.sort()
    return [("npm", name, spec, lines.line(offset)) for offset, name, spec in found]
