"""Model-file analyzer (design doc 13 §4.2 `model-file`, §5.3 `modelfiles`, Appendix H.1 C21).

Identifies model files by content (magic bytes and container layout; the extension only decides
whether a file is worth opening), inventories each one as a `model-file` component and judges it
statically.

Scanned model files are hostile input. Nothing in this module unpickles, unmarshals, imports or
executes anything taken from a file:

* pickle bytecode is walked with `pickletools.genops` only. A small symbolic stack tracks
  constants, tuples, dicts and the memo, so `STACK_GLOBAL` operands that were built through
  `MEMOIZE`/`BINPUT` and fetched back with `BINGET` still resolve to the imported callable;
* every read is bounded: opcode arguments above `elide_arg_bytes` are skipped instead of being
  materialised, protocol-0 lines are length-limited, decompression is streamed with output caps
  (zip bombs), header/JSON/metadata reads have size caps, and opcode/field budgets stop
  pathological inputs;
* truncated or inconsistent containers become `ait.model.malformed` findings, never exceptions.

Rules, deny/allow lists and limits live in `data/ait/model-rules.json`.
"""

from __future__ import annotations

import ast
import base64
import binascii
import bz2
import gzip
import hashlib
import io
import itertools
import json
import lzma
import math
import pickletools
import re
import struct
import tempfile
import zipfile
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import data, knownhashes, sources
from .model import Component, Evidence, Finding, Location
from .walk import rel_posix

try:  # the tables the stdlib unpickler applies to Python 2 names (fix_imports); data only
    import _compat_pickle

    _PY2_MODULES: dict[str, str] = dict(_compat_pickle.IMPORT_MAPPING)
    _PY2_NAMES: dict[tuple[str, str], tuple[str, str]] = dict(_compat_pickle.NAME_MAPPING)
except ImportError:  # pragma: no cover - CPython always ships it
    _PY2_MODULES, _PY2_NAMES = {}, {}

MODEL_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib", ".safetensors", ".gguf",
        ".onnx", ".h5", ".hdf5", ".keras", ".tflite", ".mar", ".pte", ".npy", ".npz",
    }
)
# `model.joblib.gz`, `clf.pkl.z`, ...: joblib picks the compressor from these suffixes.
_COMPRESSION_SUFFIXES = frozenset({".gz", ".z", ".bz2", ".xz", ".lzma", ".lz4"})
_COMPRESSIBLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".joblib", ".pt", ".pth", ".npy"})
# A `.bin` is anything; when sniffing finds no model format it is simply not a model.
_GENERIC_EXTENSIONS = frozenset({".bin"})
_PICKLE_EXTENSIONS = frozenset({".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib"})
# Extensions whose format has a signature we check; a missing signature is malformed.
_SIGNED_EXTENSIONS = frozenset({".safetensors", ".gguf", ".h5", ".hdf5", ".npy", ".npz", ".keras", ".mar"})
_EXT_FORMAT = {
    ".pt": "pytorch", ".pth": "pytorch", ".ckpt": "checkpoint", ".pkl": "pickle", ".pickle": "pickle",
    ".joblib": "joblib", ".safetensors": "safetensors", ".gguf": "gguf", ".onnx": "onnx",
    ".h5": "hdf5", ".hdf5": "hdf5", ".keras": "keras", ".tflite": "tflite", ".mar": "torchserve-mar",
    ".pte": "executorch", ".npy": "numpy-npy", ".npz": "numpy-npz", ".bin": "unknown",
}
# Formats an extension legitimately holds (anything else is recorded as `extension_mismatch`).
_EXT_ACCEPT = {
    ".safetensors": {"safetensors"}, ".gguf": {"gguf"}, ".onnx": {"onnx"}, ".tflite": {"tflite"},
    ".h5": {"hdf5", "keras-h5"}, ".hdf5": {"hdf5", "keras-h5"}, ".keras": {"keras", "keras-h5"},
    ".npy": {"numpy-npy"}, ".npz": {"numpy-npz"}, ".mar": {"torchserve-mar"},
}
# Extensions of formats that cannot execute code; pickle content behind them is a disguise.
_NON_EXEC_EXTENSIONS = frozenset({".safetensors", ".gguf", ".onnx", ".tflite", ".h5", ".hdf5"})
_PICKLE_FORMATS = frozenset({"pickle", "pytorch-legacy", "joblib", "pytorch-zip", "torchscript", "zip-pickle"})

_HDF5_SIG = b"\x89HDF\r\n\x1a\n"
_GGML_MAGICS = {b"lmgg": "ggml", b"fmgg": "ggmf", b"tjgg": "ggjt", b"algg": "ggla"}  # uint32 LE
_TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
_PROTO01_FIRST = frozenset(b"(c}])NILFSVXUTKMJGP")  # plausible first opcodes of protocol 0/1
_PICKLE_MEMBER_SUFFIXES = (".pkl", ".pickle")

_DEFAULT_LIMITS: dict[str, int] = {
    "max_pickle_opcodes": 3_000_000,
    "max_pickles_per_stream": 64,
    "max_distinct_callables": 20_000,
    "max_decompressed_bytes": 1 << 30,
    "max_total_decompressed_bytes": 2 << 30,
    "max_line_bytes": 16 << 20,
    "elide_arg_bytes": 1 << 20,
    "max_tracked_string": 4096,
    "max_tracked_container": 256,
    "max_zip_members": 100_000,
    "max_nested_depth": 2,
    "max_nested_member_bytes": 1 << 30,
    "max_json_bytes": 16 << 20,
    "max_npy_header_bytes": 65536,
    "max_safetensors_header_bytes": 100_000_000,
    "max_safetensors_header_parse_bytes": 32 << 20,
    "max_compression_ratio": 200,
    "compression_ratio_floor_bytes": 256 << 20,
    "max_memo_entries": 1_000_000,
    "max_tracked_string_bytes": 32 << 20,
    "max_gguf_templates": 64,
    "max_gguf_template_bytes": 4 << 20,
    "max_gguf_kv": 100_000,
    "max_gguf_array": 50_000_000,
    "max_gguf_string_store": 1 << 20,
    "hdf5_head_bytes": 32 << 20,
    "hdf5_tail_bytes": 8 << 20,
    "max_onnx_fields": 20_000_000,
    "max_onnx_nodes": 2_000_000,
    "max_onnx_depth": 16,
    "evidence_per_finding": 5,
    "max_listed": 50,
}


# --------------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------------


def is_model_candidate(path: Path) -> bool:
    """Cheap pre-filter by extension (content is sniffed later by `analyze_model_file`)."""
    suffixes = [s.lower() for s in Path(path).suffixes[-2:]]
    if not suffixes:
        return False
    if suffixes[-1] in MODEL_EXTENSIONS:
        return True
    return (
        len(suffixes) == 2
        and suffixes[-1] in _COMPRESSION_SUFFIXES
        and suffixes[0] in _COMPRESSIBLE_EXTENSIONS
    )


def is_pickle_family(name: str, fmt: str | None) -> bool:
    """True when a model file can carry pickle code: by its sniffed format, else by its extension."""
    return fmt in _PICKLE_FORMATS or _effective_ext(name) in _PICKLE_EXTENSIONS


def analyze(root: Path, files: list[Path], result=None) -> tuple[list[Component], list[Finding]]:
    """Inventory and judge every model file among `files`. Given a `result`, records the coverage:
    a file is counted when it is a model candidate, and has data when it is a model with findings."""
    components: list[Component] = []
    findings: list[Finding] = []
    entry = result.examine(sources.MODEL_FILES.name) if result is not None else None
    for path in files:
        if not is_model_candidate(path):
            continue
        if entry is not None:
            entry.checked += 1  # before the analysis: a file that makes it fail was still looked at
        comp, found = analyze_model_file(path, root)
        if comp is not None:
            components.append(comp)
            if entry is not None and found:
                entry.with_data += 1
        findings.extend(found)
    return components, findings


def analyze_model_file(path: Path, root: Path) -> tuple[Component | None, list[Finding]]:
    """Inventory and judge one model file. Returns (None, []) when the file is not a model."""
    path = Path(path)
    rel = rel_posix(path, Path(root))
    ext = _effective_ext(path.name)
    try:
        if not path.is_file():
            return None, []
        size = path.stat().st_size
    except OSError:
        return None, []
    if size == 0:
        return None, []

    ctx = _Ctx(rel, _compiled_rules(), size)
    digest = None
    known: knownhashes.Match | None = None
    info: dict[str, Any] | None
    try:
        with open(path, "rb") as fh:
            digest, sha1 = _digests(fh)
            known = knownhashes.lookup(digest, sha1)
            try:
                info = _analyze(ctx, fh, size, path.name, ext, 0, "")
            except Exception as exc:  # last line of defence: hostile bytes never crash a scan
                if ctx.sniffed is None and ext in _GENERIC_EXTENSIONS and known is None:
                    return None, []
                ctx.malformed("analysis-error", "Analysis aborted on unexpected content", {"error": _err(exc)}, {})
                info = {
                    "format": ctx.sniffed or _EXT_FORMAT.get(ext, "unknown"),
                    "format_confidence": "magic" if ctx.sniffed else "extension-only",
                }
    except OSError as exc:
        if ext in _GENERIC_EXTENSIONS:
            return None, []
        ctx.incomplete("unreadable", "Model file could not be read", {"error": _err(exc)}, {})
        info = {"format": _EXT_FORMAT.get(ext, "unknown"), "format_confidence": "extension-only"}
    if info is None:
        if known is None:
            return None, []
        # Not a model format, but the exact bytes an incident report names: report it anyway.
        info = {"format": ctx.sniffed or _EXT_FORMAT.get(ext, "unknown"), "format_confidence": "extension-only"}
    if known is not None:
        _known_bad_finding(ctx, path.name, known)

    licence = info.pop("_licence", None)
    props: dict[str, Any] = {"path": rel, "format": info.pop("format"), "size": size}
    props.update({k: v for k, v in info.items() if v is not None})
    if ctx.callables:
        names = sorted(f"{m}.{n}" for (m, n, resolved) in ctx.callables if resolved)
        if names:
            props["pickle_globals"] = names[:200]
    if ctx.callables_overflow:
        props["pickle_globals_not_tracked"] = ctx.callables_overflow
    component = Component(
        name=path.name,
        ctype="model-file",
        locations=[Location(rel)],
        hashes={"sha256": digest} if digest else {},
        licence=licence,
        ai=True,
        source="file",
        properties=_jsonable(props),
    )
    _pickle_findings(ctx)
    return component, [_to_finding(ctx, component, raw) for raw in ctx.findings()]


_DIGEST_CHUNK = 4 << 20


def _digests(fh) -> tuple[str, str]:
    """SHA-256 and SHA-1 of the whole file in one read. SHA-1 only matches the reports that
    publish nothing else; it is no integrity check (`usedforsecurity=False` keeps FIPS builds working).

    Past the first chunk each hash runs on its own thread while this one reads the next chunk:
    hashlib lets go of the GIL while it hashes a large buffer, so a multi-gigabyte model is hashed
    in half the time (0.5 s/GiB instead of 1.0 s/GiB from the file cache, 8-core laptop). Both
    updates of a chunk finish before the next chunk's start, so each hash sees the chunks in order
    and at most two chunks are held."""
    sha256, sha1 = hashlib.sha256(), hashlib.sha1(usedforsecurity=False)
    chunk = fh.read(_DIGEST_CHUNK)
    if len(chunk) < _DIGEST_CHUNK:  # small file (or a reader that returns less): not worth threads
        while chunk:
            sha256.update(chunk)
            sha1.update(chunk)
            chunk = fh.read(_DIGEST_CHUNK)
        return sha256.hexdigest(), sha1.hexdigest()
    with ThreadPoolExecutor(2, thread_name_prefix="aiterprise-digest") as pool:
        pending: tuple = ()
        while chunk:
            for f in pending:
                f.result()
            pending = (pool.submit(sha256.update, chunk), pool.submit(sha1.update, chunk))
            chunk = fh.read(_DIGEST_CHUNK)
        for f in pending:
            f.result()
    return sha256.hexdigest(), sha1.hexdigest()


def _known_bad_finding(ctx: _Ctx, name: str, known: knownhashes.Match) -> None:
    e = known.entry
    detail = {known.algorithm: known.digest, "list_version": known.version}
    detail.update({k: e[k] for k in ("file", "kind", "repository", "incident", "source", "reported") if e.get(k)})
    title = f"{name} is a known-malicious file: {e.get('incident', 'named in an incident report')}"
    ctx.add("ait.model.known-bad-hash", f"{title} ({e.get('source', 'report')}, {e.get('reported', 'undated')})",
            [detail], url=e.get("url"))


# --------------------------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Entry:
    module: str
    names: tuple[str, ...]
    submodules: bool
    classes_only: bool
    category: str
    severity: str | None
    verdict: str | None
    note: str

    @property
    def label(self) -> str:
        pats = "|".join(self.names) if self.names else "<classes>"
        return f"{self.module}{'.**' if self.submodules else ''}:{pats}"

    def _covers(self, module: str) -> bool:
        return module == self.module or (self.submodules and module.startswith(self.module + "."))

    def denies(self, module: str, name: str) -> bool:
        return self._covers(module) and any(fnmatchcase(name, p) for p in self.names)

    def allows(self, module: str, name: str) -> bool:
        if not self._covers(module):
            return False
        if self.classes_only:
            return "." not in name and name[:1].isupper()
        for pat in self.names:
            if "." in name and "." not in pat:
                continue  # a dotted (traversing) name is never covered by an undotted pattern
            if fnmatchcase(name, pat):
                return True
        return False


def _entry(raw: dict[str, Any]) -> _Entry:
    return _Entry(
        module=raw["module"],
        names=tuple(raw.get("names", ())),
        submodules=bool(raw.get("submodules", False)),
        classes_only=bool(raw.get("classes_only", False)),
        category=raw.get("category", ""),
        severity=raw.get("severity"),
        verdict=raw.get("verdict"),
        note=raw.get("note", ""),
    )


class _Rules:
    def __init__(self, raw: dict[str, Any]) -> None:
        self.meta: dict[str, dict[str, Any]] = raw["rules"]
        self.limits = {**_DEFAULT_LIMITS, **raw.get("limits", {})}
        pk = raw["pickle"]
        self.aliases = {**_PY2_MODULES, **pk.get("module_aliases", {})}
        self.deny = [_entry(e) for e in pk["deny"]]
        self.allow = [_entry(e) for e in pk["allow"]]
        gg = raw["gguf"]
        self.template_prefix: str = gg.get("chat_template_key_prefix", "tokenizer.chat_template")
        self.ssti = [(m["id"], re.compile(m["regex"])) for m in gg["ssti_markers"]]
        ox = raw["onnx"]
        self.onnx_standard = frozenset(ox["standard_domains"])
        self.onnx_vendor: dict[str, str] = dict(ox["vendor_domains"])
        self.keras_tokens = [t.encode("ascii") for t in raw["keras"]["lambda_code_tokens"]]
        self._cache: dict[tuple[str, str], tuple[str, _Entry | None, str]] = {}

    def _variants(self, module: str, name: str) -> list[tuple[str, str]]:
        out = [(module, name)]
        mapped = self.aliases.get(module)
        if mapped and mapped != module:
            out.append((mapped, name))
        pair = _PY2_NAMES.get((module, name))
        if pair and pair not in out:
            out.append(pair)
        return out

    def classify(self, module: str, name: str) -> tuple[str, _Entry | None, str]:
        """('deny' | 'allow' | 'unknown', matching entry, callable the entry matched)."""
        key = (module, name)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        result: tuple[str, _Entry | None, str] = ("unknown", None, f"{module}.{name}")
        variants = self._variants(module, name)
        found = False
        for mod, nm in variants:
            for cand_mod, cand_name in _traversals(mod, nm):
                for entry in self.deny:
                    if entry.denies(cand_mod, cand_name):
                        result = ("deny", entry, f"{cand_mod}.{cand_name}")
                        found = True
                        break
                if found:
                    break
            if found:
                break
        if not found and not _is_traversal(name):
            for mod, nm in variants:
                entry = next((e for e in self.allow if e.allows(mod, nm)), None)
                if entry is not None:
                    result = ("allow", entry, f"{mod}.{nm}")
                    break
        if len(self._cache) < 100_000:
            self._cache[key] = result
        return result


def _traversals(module: str, name: str):
    """(module, attribute) pairs a protocol-4 dotted name can reach.

    `torch` + `serialization.os.system` resolves through the `os` attribute of
    `torch.serialization`, so the window (`os`, `system`) must be checked against the deny list.
    """
    yield module, name
    parts = name.split(".")
    for j in range(1, len(parts)):
        yield module + "." + ".".join(parts[:j]), ".".join(parts[j:])
    for i in range(1, len(parts) - 1):
        for j in range(i + 1, len(parts)):
            yield ".".join(parts[i:j]), ".".join(parts[j:])


def _is_traversal(name: str) -> bool:
    """A dotted name that walks through a non-class attribute (`Class.method` is not traversal)."""
    parts = name.split(".")
    return any(not p[:1].isupper() for p in parts[:-1])


@lru_cache(maxsize=1)
def _compiled_rules() -> _Rules:
    return _Rules(data.load("model-rules.json"))


# --------------------------------------------------------------------------------------------
# Per-file analysis context and finding assembly
# --------------------------------------------------------------------------------------------


class _Incomplete(Exception):
    """A budget or cap ran out, or content cannot be followed: incomplete, not malformed."""


class _Malformed(Exception):
    """Structural error in a container."""


class _Ctx:
    def __init__(self, rel: str, rules: _Rules, size: int) -> None:
        self.rel = rel
        self.rules = rules
        self.limits = lim = rules.limits
        # (module, name, resolved) -> {"count", "occurrences", "invoked"}
        self.callables: dict[tuple[str, str, bool], dict[str, Any]] = {}
        self.callables_overflow = 0
        self.pickle_streams = 0
        self.ops_left = lim["max_pickle_opcodes"]
        # Zip-bomb guard: decompressed output is capped absolutely and relative to the file's own
        # size; the floor lets small, highly compressible (e.g. zero-filled) files still open.
        self.decompress_left = min(
            lim["max_total_decompressed_bytes"],
            max(size * lim["max_compression_ratio"], lim["compression_ratio_floor_bytes"]),
        )
        self.sniffed: str | None = None
        self._findings: dict[tuple[str, str], dict[str, Any]] = {}

    def add(self, rule_id: str, title: str, details: list[dict[str, Any]], disc: str = "", **override: Any) -> None:
        key = (rule_id, disc)
        cur = self._findings.get(key)
        if cur is None:
            self._findings[key] = {
                "rule_id": rule_id, "title": title, "details": list(details), "disc": disc, "override": override,
            }
            return
        room = self.limits["max_listed"] - len(cur["details"])
        if room > 0:
            cur["details"].extend(details[:room])
        for k, v in override.items():  # the first override for a key wins
            cur["override"].setdefault(k, v)

    def malformed(self, issue: str, title: str, detail: dict[str, Any] | None, where: dict[str, Any]) -> None:
        self.add("ait.model.malformed", title, [{"issue": issue, **where, **(detail or {})}], disc=f"{issue}:{_label(where)}")

    def incomplete(self, issue: str, title: str, detail: dict[str, Any] | None, where: dict[str, Any]) -> None:
        self.add(
            "ait.model.not-analysable", title, [{"issue": issue, **where, **(detail or {})}], disc=f"{issue}:{_label(where)}"
        )

    def findings(self) -> list[dict[str, Any]]:
        return list(self._findings.values())


def _label(where: dict[str, Any]) -> str:
    return str(where.get("member") or where.get("stream") or "")


def _to_finding(ctx: _Ctx, component: Component, raw: dict[str, Any]) -> Finding:
    meta = ctx.rules.meta[raw["rule_id"]]
    over = raw["override"]
    refs = meta.get("references") or []
    url = over.get("url") or (refs[0] if refs else None)
    details = raw["details"] or [{}]
    evidence = [
        Evidence(source="ait-rules", record=raw["rule_id"], url=url, detail=_jsonable({k: v for k, v in d.items() if v is not None}))
        for d in details
    ]
    return Finding(
        rule_id=raw["rule_id"],
        title=raw["title"],
        severity=over.get("severity", meta["severity"]),
        verdict=over.get("verdict", meta["verdict"]),
        confidence=int(over.get("confidence", meta["confidence"])),
        component=component,
        evidence=evidence,
        remediation=meta.get("remediation", ""),
        maps_to=list(meta.get("maps_to", [])),
        discriminator=raw["disc"],
    )


def _pickle_findings(ctx: _Ctx) -> None:
    """Classify every imported callable and turn the result into findings."""
    rules, lim = ctx.rules, ctx.limits
    dangerous: list[tuple[str, str, _Entry, dict[str, Any]]] = []
    unknown: dict[str, list[tuple[str, dict[str, Any], bool]]] = {}
    unresolved: list[tuple[str, dict[str, Any]]] = []
    for (module, name, resolved), info in ctx.callables.items():
        if not resolved:
            unresolved.append((name, info))
            continue
        verdict, entry, matched = rules.classify(module, name)
        callable_ = f"{module}.{name}"
        if verdict == "deny" and entry is not None:
            dangerous.append((callable_, matched, entry, info))
        elif verdict == "unknown":
            top = module.split(".")[0] or module or "?"
            unknown.setdefault(top, []).append((callable_, info, _is_traversal(name)))

    for callable_, matched, entry, info in sorted(dangerous, key=lambda x: x[0]):
        details = []
        for i, occ in enumerate(info["occurrences"]):
            d: dict[str, Any] = {"callable": callable_, **occ}
            if i == 0:
                d.update(
                    matched_rule=entry.label, category=entry.category, occurrences=info["count"], invoked=info["invoked"]
                )
                if matched != callable_:
                    d["resolves_to"] = matched
                if entry.note:
                    d["note"] = entry.note
            details.append(d)
        over: dict[str, Any] = {}
        if entry.severity:
            over["severity"] = entry.severity
        if entry.verdict:
            over["verdict"] = entry.verdict
        ctx.add(
            "ait.model.pickle.dangerous-global",
            f"Pickle imports dangerous callable {callable_} ({entry.category})",
            details,
            disc=callable_,
            **over,
        )

    for top, items in sorted(unknown.items()):
        items.sort(key=lambda x: x[0])
        traversal = any(t for _, _, t in items)
        details = []
        for c, info, t in items[: lim["max_listed"]]:
            d = {"callable": c, **info["occurrences"][0], "occurrences": info["count"], "invoked": info["invoked"]}
            if t:
                d["attribute_traversal"] = True
            details.append(d)
        if len(items) == 1:
            title = f"Pickle imports {items[0][0]}, which is not on the known-safe list"
        else:
            title = f"Pickle imports {len(items)} callables from '{top}' that are not on the known-safe list"
        ctx.add(
            "ait.model.pickle.unknown-global", title, details, disc=f"unknown:{top}",
            **({"severity": "high"} if traversal else {}),
        )

    if unresolved:
        details = [{"callable": name, **occ} for name, info in unresolved for occ in info["occurrences"]]
        ctx.add(
            "ait.model.pickle.unresolved-global",
            "Pickle imports a callable whose name cannot be resolved statically",
            details[: lim["max_listed"]],
            disc="unresolved",
        )

    if ctx.pickle_streams and not dangerous and not unknown and not unresolved:
        ctx.add(
            "ait.model.pickle.format",
            "Pickle-based model file: loading it can execute code (prefer safetensors)",
            [{
                "pickle_streams": ctx.pickle_streams,
                "callables": sorted(f"{m}.{n}" for (m, n, _r) in ctx.callables)[: lim["max_listed"]],
            }],
        )


# --------------------------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------------------------


def _effective_ext(name: str) -> str:
    suffixes = [s.lower() for s in Path(name).suffixes]
    if not suffixes:
        return ""
    if suffixes[-1] in _COMPRESSION_SUFFIXES and len(suffixes) >= 2 and suffixes[-2] in _COMPRESSIBLE_EXTENSIONS:
        return suffixes[-2]
    return suffixes[-1]


def _sniff(head: bytes, size: int) -> str | None:
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:4] == b"GGUF":
        return "gguf"
    if head[:4] in _GGML_MAGICS:
        return "ggml"
    if head[:8] == _HDF5_SIG:
        return "hdf5"
    if head[:6] == b"\x93NUMPY":
        return "npy"
    # Before the pickle check: a header length such as 0x0280 starts with bytes 80 02.
    if len(head) >= 9 and head[8:9] == b"{":
        n = struct.unpack("<Q", head[:8])[0]
        if 2 <= n <= size - 8:
            return "safetensors"
    if head[4:8] == b"TFL3":
        return "tflite"
    if len(head) >= 2 and head[0] == 0x80 and head[1] <= 5:
        return "pickle"
    if head[:4] == b"ZF0x":
        return "joblib-zf"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:4] == b"\x04\x22\x4d\x18":
        return "lz4"
    if len(head) >= 2 and head[0] == 0x78 and (head[0] * 256 + head[1]) % 31 == 0:
        return "zlib"
    if head[:3] == b"\x5d\x00\x00":
        return "lzma"
    if head[257:262] == b"ustar":
        return "tar"
    return None


_COMPRESSED_KINDS = frozenset({"joblib-zf", "gzip", "bz2", "xz", "lzma", "lz4", "zlib"})


def _analyze(ctx: _Ctx, fh, size: int, name: str, ext: str, depth: int, container: str) -> dict[str, Any] | None:
    """Analyse one (possibly nested) file. `container` labels it inside an outer archive."""
    where = {"member": container} if container else {}
    fh.seek(0)
    head = fh.read(512)
    kind = _sniff(head, size)
    if depth == 0:
        ctx.sniffed = kind
    info: dict[str, Any] | None
    if kind == "zip":
        info = _analyze_zip(ctx, fh, size, ext, depth, container)
    elif kind == "gguf":
        info = _analyze_gguf(ctx, fh, size, where)
    elif kind == "ggml":
        info = {"format": "ggml", "format_confidence": "magic", "ggml_variant": _GGML_MAGICS[head[:4]]}
        if head[:4] != b"lmgg" and len(head) >= 8:
            info["ggml_version"] = struct.unpack("<I", head[4:8])[0]
    elif kind == "safetensors":
        info = _analyze_safetensors(ctx, fh, size, where)
    elif kind == "hdf5":
        info = _analyze_hdf5(ctx, fh, size, where, 0)
    elif kind == "npy":
        fh.seek(0)
        reader = _Reader(fh, size, seekable=True, limits=ctx.limits)
        info = {"format": "numpy-npy", "format_confidence": "magic", **_npy_stream(ctx, reader, where)}
    elif kind == "tflite":
        info = _tflite_info(fh, size)
    elif kind == "pickle":
        info = _analyze_raw_pickle(ctx, fh, size, ext, where, definite=True)
    elif kind in _COMPRESSED_KINDS:
        info = _analyze_compressed(ctx, fh, kind, ext, where)
    elif kind == "tar":
        if ext in _GENERIC_EXTENSIONS and ext not in _PICKLE_EXTENSIONS:
            return None
        ctx.incomplete(
            "tar", "TAR container (e.g. the pre-0.4 PyTorch tar format) is not analysed; its contents are unknown", None, where
        )
        info = {"format": "tar", "format_confidence": "magic"}
    else:
        info = _analyze_unsniffed(ctx, fh, size, head, ext, where)
    if info is not None:
        _check_extension(ctx, ext, info, where)
    return info


def _analyze_unsniffed(ctx: _Ctx, fh, size: int, head: bytes, ext: str, where: dict[str, Any]) -> dict[str, Any] | None:
    if ext in (".h5", ".hdf5", ".keras"):
        off = _hdf5_userblock_offset(fh, size)
        if off is not None:
            return _analyze_hdf5(ctx, fh, size, where, off)
    # Protocol 0/1 pickles have no header. Try them before any extension-specific fallback, so
    # a pickle disguised as `.safetensors` / `.onnx` is still walked.
    if head[:1] and head[0] in _PROTO01_FIRST:
        info = _analyze_raw_pickle(ctx, fh, size, ext, where, definite=False)
        if info is not None:
            return info
    if ext == ".onnx":
        return _analyze_onnx(ctx, fh, size, where)
    if ext == ".safetensors" and len(head) >= 8:
        info = _analyze_safetensors(ctx, fh, size, where)  # reports the broken header
        info["format_confidence"] = "extension-only"
        return info
    if ext == ".pte":
        info = {"format": "executorch", "format_confidence": "extension-only"}
        ident = head[4:8]
        if len(ident) == 4 and all(0x20 < b < 0x7F for b in ident):
            info["flatbuffer_identifier"] = ident.decode("ascii")
        return info
    if ext == ".tflite":
        return {"format": "tflite", "format_confidence": "extension-only"}
    if ext in _GENERIC_EXTENSIONS or not ext:
        return None
    fmt = _EXT_FORMAT.get(ext, "unknown")
    if ext in _SIGNED_EXTENSIONS:
        ctx.malformed("missing-signature", f"File named {ext} lacks the {fmt} signature", {"extension": ext}, where)
    else:
        ctx.incomplete(
            "unrecognised-format", "Content is not recognised as any supported model format", {"extension": ext}, where
        )
    return {"format": fmt, "format_confidence": "extension-only"}


def _check_extension(ctx: _Ctx, ext: str, info: dict[str, Any], where: dict[str, Any]) -> None:
    accept = _EXT_ACCEPT.get(ext)
    fmt = info.get("format")
    if accept is None or fmt in accept or info.get("format_confidence") == "extension-only":
        return
    info["extension_mismatch"] = True
    if ext in _NON_EXEC_EXTENSIONS and fmt in _PICKLE_FORMATS:
        ctx.malformed(
            "extension-mismatch",
            f"Pickle-based content disguised with a {ext} extension",
            {"extension": ext, "detected_format": fmt},
            where,
        )


# --------------------------------------------------------------------------------------------
# Bounded stream reader used for pickle walking
# --------------------------------------------------------------------------------------------


class _Elided(bytes):
    """Stand-in for a large opcode argument: reports the true length, holds no data.

    pickletools' readers only check `len(data) == n` before returning the argument, so a skipped
    multi-gigabyte BINBYTES8 costs a seek instead of an allocation.
    """

    def __new__(cls, n: int):
        obj = super().__new__(cls)
        obj.n = n
        return obj

    def __len__(self) -> int:
        return self.n


class _Reader:
    """Forward-only, bounded file-like object handed to `pickletools.genops`.

    `end` is an absolute bound: the true size for files and zip members, or a cap for
    decompressed streams (`capped_end`), in which case hitting it marks the reader `capped`.
    """

    def __init__(self, raw, end: int, *, limits: dict[str, int], seekable: bool = False,
                 capped_end: bool = False, crc: bool = False) -> None:
        self._raw = raw
        self._pos = 0
        self._end = max(0, end)
        self._seekable = seekable
        self._capped_end = capped_end
        self._pending = b""
        self._elide = limits["elide_arg_bytes"]
        self._max_line = limits["max_line_bytes"]
        self.crc: int | None = 0 if crc else None
        self.elided = False
        self.capped = False

    def tell(self) -> int:
        return self._pos

    def _room(self, n: int) -> int:
        room = self._end - self._pos
        if n > room:
            if self._capped_end:
                self.capped = True
            return max(room, 0)
        return n

    def _advance(self, chunk: bytes) -> None:
        self._pos += len(chunk)
        if self.crc is not None:
            self.crc = zlib.crc32(chunk, self.crc)

    def _take(self, n: int) -> bytes:
        parts = []
        got = 0
        if self._pending:
            part = self._pending[:n]
            self._pending = self._pending[len(part):]
            parts.append(part)
            got = len(part)
        while got < n:
            chunk = self._raw.read(n - got)
            if not chunk:
                break
            parts.append(chunk)
            got += len(chunk)
        out = b"".join(parts)
        self._advance(out)
        return out

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            raise ValueError("unbounded read refused")
        if n > self._elide:
            got = self.skip(n)
            self.elided = True
            return _Elided(got)
        return self._take(self._room(n))

    def readline(self, size: int = -1) -> bytes:
        n = self._room(self._max_line)
        head = b""
        if self._pending:
            i = self._pending.find(b"\n", 0, n)
            if i >= 0:
                line = self._pending[: i + 1]
                self._pending = self._pending[i + 1:]
                self._advance(line)
                return line
            head = self._pending[:n]
            self._pending = self._pending[len(head):]
        rest = n - len(head)
        tail = self._raw.readline(rest) if rest > 0 else b""
        line = head + tail
        self._advance(line)
        return line

    def peek(self, n: int) -> bytes:
        n = min(n, max(self._end - self._pos, 0))
        while len(self._pending) < n:
            chunk = self._raw.read(n - len(self._pending))
            if not chunk:
                break
            self._pending += chunk
        return self._pending[:n]

    def skip(self, n: int) -> int:
        want = self._room(n)
        done = 0
        if self._pending:
            take = min(want, len(self._pending))
            self._advance(self._pending[:take])
            self._pending = self._pending[take:]
            done = take
        if done < want and self._seekable and self.crc is None:
            step = want - done  # `end` is the file size here, so this never passes EOF
            self._raw.seek(step, io.SEEK_CUR)
            self._pos += step
            return want
        while done < want:
            chunk = self._raw.read(min(1 << 20, want - done))
            if not chunk:
                break
            self._advance(chunk)
            done += len(chunk)
        return done

    def drain(self) -> int:
        return self.skip(self._end - self._pos)


class _ZlibRaw(io.RawIOBase):
    """Streaming zlib decompressor with bounded output per read (zip-bomb safe)."""

    def __init__(self, fh) -> None:
        self._fh = fh
        self._d = zlib.decompressobj()
        self._eof = False

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        want = len(b)
        if want == 0:
            return 0
        out = b""
        while not out and not self._eof:
            if self._d.unconsumed_tail:
                out = self._d.decompress(self._d.unconsumed_tail, want)
            else:
                chunk = self._fh.read(1 << 16)
                if not chunk:
                    self._eof = True
                    if not self._d.eof:
                        raise zlib.error("truncated zlib stream")
                    break
                out = self._d.decompress(chunk, want)
            if self._d.eof and not self._d.unconsumed_tail:
                self._eof = True
        b[: len(out)] = out
        return len(out)


# --------------------------------------------------------------------------------------------
# Pickle opcode walk
# --------------------------------------------------------------------------------------------


class _Unknown:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<?>"


_UNK = _Unknown()
_MARK = object()


class _Global:
    __slots__ = ("module", "name", "info")

    def __init__(self, module: str, name: str, info: dict[str, Any]) -> None:
        self.module, self.name, self.info = module, name, info


class _Obj:
    """Result of REDUCE/NEWOBJ/INST/OBJ: the callable, its args and the BUILD state."""

    __slots__ = ("func", "args", "state")

    def __init__(self, func: Any, args: Any) -> None:
        self.func, self.args, self.state = func, args, None


@dataclass
class _Walk:
    result: Any = _UNK
    complete: bool = False
    protocol: int | None = None
    error: str | None = None
    incomplete: str | None = None
    error_offset: int | None = None
    opcodes: int = 0


@dataclass
class _Stream:
    count: int = 0
    protocol: int | None = None
    legacy: bool = False
    first_ok: bool = False
    trailing: bool = False
    error: str | None = None
    incomplete: str | None = None
    error_offset: int | None = None
    error_index: int | None = None
    end: int = 0


_STR_OPS = frozenset({"STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8"})
_BYTES_OPS = frozenset({"BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8"})
_NUM_OPS = frozenset({"INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "FLOAT", "BINFLOAT"})
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_EXT_OPS = frozenset({"EXT1", "EXT2", "EXT4"})
_IDENTISH = re.compile(r"[\w.]+")


def _err(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:300]


def _describe(v: Any) -> str:
    if isinstance(v, str):
        return v[:100]
    if isinstance(v, _Global):
        return f"<result of {v.module}.{v.name}>"
    if v is _UNK:
        return "<unknown>"
    return f"<{type(v).__name__}>"


def _clip(s: str, n: int = 512) -> str:
    # An over-long module/name cannot be imported, so the clipped form (which no longer matches
    # any list entry exactly) is still a faithful classification.
    return s if len(s) <= n else s[:n] + "...[truncated]"


def _note_callable(ctx: _Ctx, module: str, name: str, opcode: str, pos: int | None,
                   where: dict[str, Any], index: Any, resolved: bool = True) -> _Global:
    module, name = _clip(module), _clip(name)
    key = (module, name, resolved)
    info = ctx.callables.get(key)
    if info is None:
        if (
            len(ctx.callables) >= ctx.limits["max_distinct_callables"]
            and resolved
            and ctx.rules.classify(module, name)[0] != "deny"
        ):
            ctx.callables_overflow += 1
            return _Global(module, name, {"invoked": False})
        info = {"count": 0, "occurrences": [], "invoked": False}
        ctx.callables[key] = info
    info["count"] += 1
    if len(info["occurrences"]) < ctx.limits["evidence_per_finding"]:
        occ: dict[str, Any] = {"opcode": opcode, "offset": pos, "pickle": index}
        occ.update(where)
        info["occurrences"].append(occ)
    return _Global(module, name, info)


def _invoked(v: Any) -> None:
    if isinstance(v, _Global):
        v.info["invoked"] = True


def _dict_update(d: dict, items: list, cap: int) -> None:
    for i in range(0, len(items) - 1, 2):
        if len(d) >= cap:
            return
        try:
            d[items[i]] = items[i + 1]
        except TypeError:  # unhashable key (list/dict): irrelevant to the analysis
            pass


def _walk_one(ctx: _Ctx, reader: _Reader, where: dict[str, Any], index: Any, nesting: int = 0) -> _Walk:
    """Walk one pickle (up to and including STOP) without executing it."""
    w = _Walk()
    if nesting > 8:
        w.error = "pickles nested too deeply"
        w.error_offset = reader.tell()
        return w
    max_str = ctx.limits["max_tracked_string"]
    max_c = ctx.limits["max_tracked_container"]
    max_memo = ctx.limits["max_memo_entries"]
    # Memory bounds. Past the string budget only short identifier-like strings (what STACK_GLOBAL
    # needs) are kept, from a second allowance of the same size. Anything dropped (string or
    # memo slot) becomes unknown, so a STACK_GLOBAL built from it is reported as unresolved:
    # the caps can cost precision, never hide an import.
    str_left = ident_left = ctx.limits["max_tracked_string_bytes"]
    stack: list[Any] = []
    memo: dict[Any, Any] = {}
    push = stack.append

    def pop() -> Any:
        return stack.pop() if stack else _UNK

    def top() -> Any:
        return stack[-1] if stack else _UNK

    def pop_mark() -> list[Any]:
        for i in range(len(stack) - 1, -1, -1):
            if stack[i] is _MARK:
                items = stack[i + 1:]
                del stack[i:]
                return items
        items = stack[:]
        stack.clear()
        return items

    def note(module: str, name: str, opcode: str, pos: int | None, resolved: bool = True) -> _Global:
        return _note_callable(ctx, module, name, opcode, pos, where, index, resolved)

    try:
        for op, arg, pos in pickletools.genops(reader):
            w.opcodes += 1
            ctx.ops_left -= 1
            if ctx.ops_left < 0:
                raise _Incomplete("pickle opcode budget exhausted")
            elided = reader.elided
            reader.elided = False
            name = op.name
            if name in _PUT_OPS:
                if stack and (len(memo) < max_memo or arg in memo):
                    memo[arg] = stack[-1]
            elif name == "MEMOIZE":
                if stack and len(memo) < max_memo:
                    memo[len(memo)] = stack[-1]
            elif name in _GET_OPS:
                push(memo.get(arg, _UNK))
            elif name in _NUM_OPS:
                push(arg)
            elif name in _STR_OPS:
                n = len(arg)
                if elided or n > max_str:
                    push(_UNK)
                elif n <= str_left:
                    str_left -= n
                    push(arg)
                elif n <= 256 and n <= ident_left and _IDENTISH.fullmatch(arg):
                    ident_left -= n
                    push(arg)
                else:
                    push(_UNK)
            elif name in _BYTES_OPS:
                push(_UNK)
            elif name == "MARK":
                push(_MARK)
            elif name == "EMPTY_TUPLE":
                push(())
            elif name == "TUPLE1":
                push((pop(),))
            elif name == "TUPLE2":
                b = pop()
                push((pop(), b))
            elif name == "TUPLE3":
                c = pop()
                b = pop()
                push((pop(), b, c))
            elif name == "TUPLE":
                items = pop_mark()
                push(tuple(items) if len(items) <= max_c else _UNK)
            elif name == "EMPTY_LIST":
                push([])
            elif name == "EMPTY_DICT":
                push({})
            elif name == "LIST":
                push(pop_mark()[:max_c])
            elif name == "DICT":
                d: dict = {}
                _dict_update(d, pop_mark(), max_c)
                push(d)
            elif name == "APPEND":
                v = pop()
                t = top()
                if type(t) is list and len(t) < max_c:
                    t.append(v)
            elif name == "APPENDS":
                items = pop_mark()
                t = top()
                if type(t) is list:
                    t.extend(items[: max(0, max_c - len(t))])
            elif name == "SETITEM":
                v = pop()
                k = pop()
                t = top()
                if type(t) is dict:
                    _dict_update(t, [k, v], max_c)
            elif name == "SETITEMS":
                items = pop_mark()
                t = top()
                if type(t) is dict:
                    _dict_update(t, items, max_c)
            elif name == "NONE":
                push(None)
            elif name == "NEWTRUE":
                push(True)
            elif name == "NEWFALSE":
                push(False)
            elif name == "GLOBAL":
                module, _, gname = arg.partition(" ")
                push(note(module, gname, name, pos))
            elif name == "STACK_GLOBAL":
                gname = pop()
                module = pop()
                if type(module) is str and type(gname) is str:
                    push(note(module, gname, name, pos))
                else:
                    push(note("?", f"{_describe(module)}.{_describe(gname)}", name, pos, resolved=False))
            elif name == "INST":
                module, _, cname = arg.partition(" ")
                items = pop_mark()
                g = note(module, cname, name, pos)
                _invoked(g)
                push(_Obj(g, tuple(items)))
            elif name == "OBJ":
                items = pop_mark()
                cls = items[0] if items else _UNK
                _invoked(cls)
                push(_Obj(cls, tuple(items[1:])))
            elif name == "REDUCE":
                args = pop()
                func = pop()
                _invoked(func)
                push(_Obj(func, args))
            elif name == "NEWOBJ":
                args = pop()
                cls = pop()
                _invoked(cls)
                push(_Obj(cls, args))
            elif name == "NEWOBJ_EX":
                pop()  # kwargs
                args = pop()
                cls = pop()
                _invoked(cls)
                push(_Obj(cls, args))
            elif name == "BUILD":
                state = pop()
                obj = top()
                if isinstance(obj, _Obj):
                    obj.state = state
                    if _is_joblib_wrapper(_obj_class(obj)):
                        _joblib_array(ctx, reader, obj, where, index, nesting)
            elif name in _EXT_OPS:
                push(note("?", f"copyreg-extension-code-{arg}", name, pos, resolved=False))
            elif name == "PERSID":
                push(_UNK)
            elif name == "BINPERSID":
                pop()
                push(_UNK)
            elif name == "POP":
                pop()
            elif name == "POP_MARK":
                pop_mark()
            elif name == "DUP":
                push(top())
            elif name == "PROTO":
                w.protocol = arg if w.protocol is None else max(w.protocol, arg)
            elif name == "FRAME":
                pass
            elif name == "STOP":
                w.result = pop()
                w.complete = True
            else:  # any other opcode: apply its declared stack effect symbolically
                before = op.stack_before
                marks = [i for i, s in enumerate(before) if s.name == "mark"]
                if marks:
                    pop_mark()
                    for _ in range(marks[0]):
                        pop()
                else:
                    for _ in before:
                        pop()
                for _ in op.stack_after:
                    push(_UNK)
    except _Incomplete as exc:
        w.incomplete = str(exc)
        w.error_offset = reader.tell()
    except Exception as exc:  # malformed / hostile bytecode: keep what was found so far
        if reader.capped:
            w.incomplete = "size cap reached while reading the pickle stream"
        else:
            w.error = _err(exc)
        w.error_offset = reader.tell()
    return w


def _walk_pickles(ctx: _Ctx, reader: _Reader, where: dict[str, Any], *, single: bool = False) -> _Stream:
    """Walk consecutive pickles (legacy torch files hold five; loaders may read several)."""
    st = _Stream()
    expected = 1 if single else None
    while True:
        w = _walk_one(ctx, reader, where, st.count)
        if w.protocol is not None:
            st.protocol = w.protocol if st.protocol is None else max(st.protocol, w.protocol)
        if not w.complete:
            if st.count == 0 or expected is not None or w.incomplete:
                st.error, st.incomplete = w.error, w.incomplete
                st.error_offset, st.error_index = w.error_offset, st.count
            else:
                st.trailing = True  # bytes after the last pickle that merely look like one
            break
        st.count += 1
        if st.count == 1:
            st.first_ok = True
            if not single and type(w.result) is int and w.result == _TORCH_LEGACY_MAGIC:
                st.legacy = True
                expected = 5  # magic, protocol version, sys_info, object, storage keys
        if expected is not None:
            if st.count >= expected:
                break
            continue
        try:
            nxt = reader.peek(2)
        except Exception:
            break
        more = len(nxt) == 2 and nxt[0] == 0x80 and nxt[1] <= 5
        if more and st.count >= ctx.limits["max_pickles_per_stream"]:
            # a loader may read every pickle in the stream: the ones past the cap are unknown
            st.incomplete = f"more than {st.count} pickles in the stream; the rest were not analysed"
            st.error_offset, st.error_index = reader.tell(), st.count
            break
        if more:
            continue
        st.trailing = bool(nxt)
        break
    st.end = reader.tell()
    return st


def _record_stream(ctx: _Ctx, st: _Stream, where: dict[str, Any]) -> None:
    if st.error:
        ctx.malformed(
            "pickle-parse",
            "Pickle stream is truncated or malformed (opcodes before the error still run on load)",
            {"error": st.error, "offset": st.error_offset, "pickle": st.error_index},
            where,
        )
    if st.incomplete:
        ctx.incomplete(
            "pickle-incomplete",
            "Pickle stream was only partially analysed",
            {"reason": st.incomplete, "offset": st.error_offset, "pickle": st.error_index},
            where,
        )


def _uses_joblib(ctx: _Ctx) -> bool:
    return any(m.startswith(("joblib.", "sklearn.externals.joblib")) for (m, _n, _r) in ctx.callables)


def _pickle_props(ctx: _Ctx, st: _Stream, ext: str, compression: str | None) -> dict[str, Any]:
    if st.legacy:
        fmt = "pytorch-legacy"
    elif ext == ".joblib" or compression == "zlib-legacy" or _uses_joblib(ctx):
        fmt = "joblib"
    else:
        fmt = "pickle"
    props: dict[str, Any] = {
        "format": fmt,
        "format_confidence": "magic" if (st.protocol or 0) >= 2 else "structure",
        "pickle_count": st.count,
        "pickle_protocol": st.protocol,
    }
    if compression:
        props["compression"] = compression
    if st.trailing:
        props["trailing_data"] = True
    return props


def _analyze_raw_pickle(ctx: _Ctx, fh, size: int, ext: str, where: dict[str, Any], *, definite: bool) -> dict[str, Any] | None:
    fh.seek(0)
    reader = _Reader(fh, size, seekable=True, limits=ctx.limits)
    before = len(ctx.callables)
    st = _walk_pickles(ctx, reader, where)
    found = len(ctx.callables) > before
    # Protocol 0/1 have no header: accept only a parse that covers the file, or one that
    # imported something (random bytes do not spell `module\nname\n`).
    if not definite and not found and not (st.first_ok and st.end == size):
        return None
    ctx.pickle_streams += 1
    _record_stream(ctx, st, where)
    return _pickle_props(ctx, st, ext, None)


# --- joblib -----------------------------------------------------------------------------------


def _obj_class(obj: _Obj) -> Any:
    f = obj.func
    if (
        isinstance(f, _Global)
        and f.name in ("_reconstructor", "__newobj__", "__newobj_ex__")
        and isinstance(obj.args, tuple)
        and obj.args
    ):
        return obj.args[0]
    return f


def _is_joblib_wrapper(cls: Any) -> bool:
    return isinstance(cls, _Global) and cls.name == "NumpyArrayWrapper" and cls.module.endswith("numpy_pickle")


_DTYPE_CODE = re.compile(r"[<>|=]?([a-zA-Z?])(\d*)")


def _dtype_info(dt: Any) -> tuple[bool, int] | None:
    """(has_object, itemsize) of a symbolically rebuilt numpy dtype, or None when unknown."""
    if not (isinstance(dt, _Obj) and isinstance(dt.func, _Global) and dt.func.module.split(".")[0] == "numpy"):
        return None
    args = dt.args
    if not (isinstance(args, tuple) and args and isinstance(args[0], str)):
        return None
    state = dt.state if isinstance(dt.state, tuple) else ()
    flags = state[7] if len(state) > 7 and type(state[7]) is int else 0
    elsize = state[5] if len(state) > 5 and type(state[5]) is int else -1
    m = _DTYPE_CODE.fullmatch(args[0])
    if not m:
        return None
    kind, digits = m.group(1), m.group(2)
    if kind == "O" or flags & 1:
        return True, 0
    if elsize > 0:
        return False, elsize
    if digits:
        n = int(digits)
        return False, n * 4 if kind == "U" else n
    if kind == "?":
        return False, 1
    return None


def _joblib_array(ctx: _Ctx, reader: _Reader, obj: _Obj, where: dict[str, Any], index: Any, nesting: int) -> None:
    """joblib writes array bytes straight after the wrapper's BUILD; step over them.

    Object arrays are written as a nested protocol-2 pickle, which is walked like any other.
    """
    state = obj.state if isinstance(obj.state, dict) else {}
    dt = _dtype_info(state.get("dtype"))
    shape = state.get("shape")
    if dt is None or not (isinstance(shape, tuple) and all(type(x) is int and x >= 0 for x in shape)):
        raise _Incomplete("joblib array payload of undeterminable size; analysis stopped there")
    has_object, itemsize = dt
    if has_object:
        sub = _walk_one(ctx, reader, where, f"{index}/object-array@{reader.tell()}", nesting + 1)
        if sub.incomplete:
            raise _Incomplete(sub.incomplete)
        if not sub.complete:
            raise ValueError(f"embedded object-array pickle: {sub.error}")
        return
    align = state.get("numpy_array_alignment_bytes")
    if type(align) is int and align > 0:
        pad = reader.read(1)
        if len(pad) != 1 or reader.skip(pad[0]) != pad[0]:
            raise ValueError("truncated joblib array padding")
    nbytes = math.prod(shape) * itemsize
    if reader.skip(nbytes) != nbytes:
        if reader.capped:
            raise _Incomplete("size cap reached inside a joblib array payload")
        raise ValueError(f"truncated joblib array data (expected {nbytes} bytes)")


# --- compressed pickles -----------------------------------------------------------------------


def _decompressing_stream(fh, kind: str):
    if kind == "gzip":
        return gzip.GzipFile(fileobj=fh, mode="rb")
    if kind == "bz2":
        return bz2.BZ2File(fh, "rb")
    if kind in ("xz", "lzma"):
        return lzma.LZMAFile(fh, "rb")  # FORMAT_AUTO: .xz and legacy .lzma
    if kind == "zlib":
        return io.BufferedReader(_ZlibRaw(fh), 1 << 16)
    if kind == "joblib-zf":  # joblib < 0.10: b"ZF" + hex length padded to 9 chars (+ optional space)
        hdr = fh.read(11)
        int(hdr[2:].decode("ascii").strip(), 16)
        if fh.read(1) != b" ":
            fh.seek(11)
        return io.BufferedReader(_ZlibRaw(fh), 1 << 16)
    raise ValueError(f"no decompressor for {kind}")


def _analyze_compressed(ctx: _Ctx, fh, kind: str, ext: str, where: dict[str, Any]) -> dict[str, Any] | None:
    compression = "zlib-legacy" if kind == "joblib-zf" else kind
    pickleish = ext in _PICKLE_EXTENSIONS or kind == "joblib-zf"
    base_fmt = "joblib" if (ext == ".joblib" or kind == "joblib-zf") else ("pickle" if pickleish else "compressed")
    if kind == "lz4":
        ctx.incomplete(
            "lz4",
            "LZ4-compressed payload cannot be decompressed with the standard library; it was not analysed (not a clean result)",
            {"compression": "lz4"},
            where,
        )
        return {"format": base_fmt if pickleish else "lz4-compressed", "format_confidence": "magic", "compression": "lz4"}
    fh.seek(0)
    try:
        raw = _decompressing_stream(fh, kind)
    except Exception as exc:
        ctx.malformed("compression-header", "Compressed stream header is invalid", {"error": _err(exc), "compression": compression}, where)
        return {"format": base_fmt, "format_confidence": "magic", "compression": compression}
    cap = max(0, min(ctx.limits["max_decompressed_bytes"], ctx.decompress_left))
    reader = _Reader(raw, cap, capped_end=True, limits=ctx.limits)
    swhere = {**where, "stream": f"{compression}-decompressed"}
    try:
        head = reader.peek(2)
    except Exception as exc:
        if ext in _GENERIC_EXTENSIONS:
            return None
        ctx.malformed("decompression", "Compressed stream cannot be decompressed", {"error": _err(exc), "compression": compression}, where)
        return {"format": base_fmt, "format_confidence": "magic", "compression": compression}
    definite = len(head) == 2 and head[0] == 0x80 and head[1] <= 5
    if not definite and not (head[:1] and head[0] in _PROTO01_FIRST):
        if ext in _GENERIC_EXTENSIONS:
            return None
        ctx.incomplete(
            "compressed-content", "Compressed payload is not a pickle and was not analysed further", {"compression": compression}, where
        )
        return {"format": base_fmt, "format_confidence": "magic", "compression": compression}
    before = len(ctx.callables)
    st = _walk_pickles(ctx, reader, swhere)
    ctx.decompress_left -= reader.tell()
    if not definite and len(ctx.callables) == before and not st.first_ok:
        if ext in _GENERIC_EXTENSIONS:
            return None
        ctx.incomplete(
            "compressed-content", "Compressed payload is not a pickle and was not analysed further", {"compression": compression}, where
        )
        return {"format": base_fmt, "format_confidence": "magic", "compression": compression}
    ctx.pickle_streams += 1
    _record_stream(ctx, st, swhere)
    props = _pickle_props(ctx, st, ext, compression)
    props["decompressed_bytes_read"] = reader.tell()
    return props


# --------------------------------------------------------------------------------------------
# NumPy .npy
# --------------------------------------------------------------------------------------------


_OBJECT_DESCR = re.compile(r"[<>|=]?O\d*")


def _descr_has_object(descr: Any, depth: int = 0) -> bool:
    if depth > 32:
        return True  # absurd nesting: assume the worst
    if isinstance(descr, str):
        return bool(_OBJECT_DESCR.fullmatch(descr.strip()))
    if isinstance(descr, list):
        for field in descr:
            if isinstance(field, (tuple, list)) and len(field) >= 2 and _descr_has_object(field[1], depth + 1):
                return True
        return False
    return False


def _npy_stream(ctx: _Ctx, reader: _Reader, where: dict[str, Any]) -> dict[str, Any]:
    """Parse an .npy header from `reader`; an object-dtype payload is a pickle and is walked."""
    if reader.read(6) != b"\x93NUMPY":
        ctx.malformed("npy-header", "NumPy .npy magic is missing", None, where)
        return {}
    ver = reader.read(2)
    if len(ver) != 2:
        ctx.malformed("npy-header", "NumPy .npy header is truncated", None, where)
        return {}
    major, minor = ver[0], ver[1]
    if major == 1:
        raw = reader.read(2)
        hlen = struct.unpack("<H", raw)[0] if len(raw) == 2 else -1
    elif major in (2, 3):
        raw = reader.read(4)
        hlen = struct.unpack("<I", raw)[0] if len(raw) == 4 else -1
    else:
        ctx.malformed("npy-header", f"Unsupported .npy format version {major}.{minor}", None, where)
        return {"npy_version": f"{major}.{minor}"}
    props: dict[str, Any] = {"npy_version": f"{major}.{minor}"}
    if hlen < 0 or hlen > ctx.limits["max_npy_header_bytes"]:
        ctx.malformed("npy-header", "NumPy .npy header length is truncated or implausible", {"header_length": hlen}, where)
        return props
    hdr = reader.read(hlen)
    if len(hdr) != hlen:
        ctx.malformed("npy-header", "NumPy .npy header is truncated", None, where)
        return props
    try:
        header = ast.literal_eval(hdr.decode("utf-8" if major >= 3 else "latin-1"))  # literals only
    except Exception as exc:
        ctx.malformed("npy-header", "NumPy .npy header is not a valid literal", {"error": _err(exc)}, where)
        return props
    if not (isinstance(header, dict) and {"descr", "fortran_order", "shape"} <= header.keys()):
        ctx.malformed("npy-header", "NumPy .npy header lacks descr/fortran_order/shape", None, where)
        return props
    descr, shape = header["descr"], header["shape"]
    has_object = _descr_has_object(descr)
    props.update(descr=str(descr)[:200], fortran_order=bool(header["fortran_order"]), object_dtype=has_object)
    if isinstance(shape, tuple) and all(type(x) is int for x in shape):
        props["shape"] = list(shape[:16])
    if has_object:
        st = _walk_pickles(ctx, reader, where, single=True)  # numpy reads exactly one pickle
        ctx.pickle_streams += 1
        _record_stream(ctx, st, where)
        props["pickle_protocol"] = st.protocol
    return props


# --------------------------------------------------------------------------------------------
# ZIP containers: PyTorch zip, TorchScript, .npz, .keras, TorchServe .mar
# --------------------------------------------------------------------------------------------


_UNSAFE_DRIVE = re.compile(r"^[A-Za-z]:")


def _unsafe_path(name: str) -> bool:
    if not name:
        return False
    if name.startswith(("/", "\\")) or _UNSAFE_DRIVE.match(name) or "\x00" in name:
        return True
    return ".." in re.split(r"[\\/]", name)


def _zip_layout(names: list[str], ext: str) -> str | None:
    s = set(names)
    if "MAR-INF/MANIFEST.json" in s:
        return "torchserve-mar"
    if "config.json" in s and ("metadata.json" in s or any(n.endswith(".weights.h5") for n in names) or ext == ".keras"):
        return "keras"
    if any(n == "data.pkl" or n.endswith("/data.pkl") for n in names):
        return "pytorch-zip"
    if names and all(n.lower().endswith(".npy") for n in names):
        return "numpy-npz"
    return None


def _analyze_zip(ctx: _Ctx, fh, size: int, ext: str, depth: int, container: str) -> dict[str, Any] | None:
    cwhere = {"member": container} if container else {}
    fh.seek(0)
    try:
        zf = zipfile.ZipFile(fh)
        infos = zf.infolist()
    except Exception as exc:
        ctx.malformed("zip-unreadable", "ZIP container cannot be read (truncated or corrupt)", {"error": _err(exc)}, cwhere)
        return {"format": _EXT_FORMAT.get(ext) if ext in _EXT_FORMAT and ext != ".bin" else "zip",
                "format_confidence": "magic", "container": "zip"}
    try:
        return _zip_members(ctx, zf, infos, ext, depth, container)
    finally:
        zf.close()


def _zip_members(ctx: _Ctx, zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], ext: str, depth: int,
                 container: str) -> dict[str, Any] | None:
    lim = ctx.limits
    cwhere = {"member": container} if container else {}

    def label(name: str) -> str:
        return f"{container}!{name}" if container else name

    total = len(infos)
    if total > lim["max_zip_members"]:
        ctx.incomplete("zip-member-cap", "Archive has more members than are analysed", {"members": total}, cwhere)
        infos = infos[: lim["max_zip_members"]]
    names = [i.filename for i in infos]
    unsafe = [n for n in names if _unsafe_path(n)]
    if unsafe:
        ctx.add(
            "ait.model.zip-slip",
            f"Archive member names escape the extraction directory ({len(unsafe)})",
            [{"members": unsafe[: lim["max_listed"]], "count": len(unsafe), **cwhere}],
            disc=container,
        )
    dups = sorted(n for n, c in Counter(names).items() if c > 1)
    if dups:
        ctx.malformed(
            "zip-duplicate-members",
            "Archive repeats member names; loaders may disagree on which copy they read",
            {"members": dups[: lim["max_listed"]]},
            cwhere,
        )

    files = [i for i in infos if not i.is_dir()]
    layout = _zip_layout([i.filename for i in files], ext)
    props: dict[str, Any] = {"format_confidence": "magic", "container": "zip", "zip_members": total}
    pickle_members: list[str] = []
    npy_members: list[str] = []
    object_arrays: list[str] = []
    py_files: list[str] = []
    nested: list[dict[str, Any]] = []
    manifest: dict[str, Any] | None = None
    for info in files:
        fname = info.filename
        low = fname.lower()
        where = {"member": label(fname)}
        if low.endswith(_PICKLE_MEMBER_SUFFIXES):
            pickle_members.append(fname)
            _zip_pickle_member(ctx, zf, info, where)
        elif low.endswith(".npy"):
            npy_members.append(fname)
            sub = _zip_npy_member(ctx, zf, info, where)
            if sub and sub.get("object_dtype"):
                object_arrays.append(fname)
        elif layout == "keras" and fname == "config.json":
            raw = _member_bytes(ctx, zf, info, where, lim["max_json_bytes"])
            if raw is not None:
                props.update(_keras_config(ctx, raw, where))
        elif layout == "keras" and fname == "metadata.json":
            meta = _json_member(ctx, zf, info, where)
            if isinstance(meta, dict) and isinstance(meta.get("keras_version"), str):
                props["keras_version"] = meta["keras_version"][:50]
        elif layout == "torchserve-mar" and fname == "MAR-INF/MANIFEST.json":
            got = _json_member(ctx, zf, info, where)
            manifest = got if isinstance(got, dict) else {}
        elif layout == "pytorch-zip" and (fname == "version" or fname.endswith("/version")):
            raw = _member_bytes(ctx, zf, info, where, 64)
            if raw is not None and raw.strip().isdigit():
                props["torch_serialization_version"] = int(raw.strip())
        elif low.endswith(".py"):
            py_files.append(fname)
        elif depth < lim["max_nested_depth"] and _nested_candidate(fname, layout):
            sub = _zip_nested(ctx, zf, info, depth, label(fname))
            if sub is not None:
                nested.append({"member": fname, "format": sub.get("format")})

    if pickle_members:
        props["pickle_members"] = pickle_members[: lim["max_listed"]]
    if nested:
        props["nested_models"] = nested[: lim["max_listed"]]

    if layout == "pytorch-zip":
        torchscript = any("/code/" in n or n.startswith("code/") or n.endswith("constants.pkl") for n in names)
        props["format"] = "torchscript" if torchscript else "pytorch-zip"
        data_pkl = next(n for n in names if n == "data.pkl" or n.endswith("/data.pkl"))
        props["archive_name"] = data_pkl.rsplit("/", 1)[0] if "/" in data_pkl else ""
    elif layout == "numpy-npz":
        props["format"] = "numpy-npz"
        props["arrays"] = len(npy_members)
        if object_arrays:
            props["object_arrays"] = object_arrays[: lim["max_listed"]]
    elif layout == "keras":
        props["format"] = "keras"
    elif layout == "torchserve-mar":
        props["format"] = "torchserve-mar"
        props.update(_mar_details(ctx, manifest or {}, py_files, cwhere, container))
    elif pickle_members:
        props["format"] = "zip-pickle"
    elif nested or npy_members:
        props["format"] = "zip"
    else:
        if ext in _GENERIC_EXTENSIONS:
            return None
        ctx.incomplete("zip-layout", "ZIP container has no recognised model layout", {"members": total}, cwhere)
        props["format"] = "zip"
    return props


def _nested_candidate(fname: str, layout: str | None) -> bool:
    ext = _effective_ext(fname.rsplit("/", 1)[-1])
    if ext not in MODEL_EXTENSIONS or ext in (".pkl", ".pickle", ".npy"):
        return False
    if layout == "keras" and ext in (".h5", ".hdf5"):
        return False  # model.weights.h5: weights only
    return True


def _open_member(ctx: _Ctx, zf: zipfile.ZipFile, info: zipfile.ZipInfo, where: dict[str, Any]):
    if info.flag_bits & 0x1:
        ctx.incomplete("zip-encrypted", "Encrypted archive member cannot be analysed", None, where)
        return None
    if ctx.decompress_left <= 0:
        ctx.incomplete("decompression-budget", "Decompression budget exhausted before this member", None, where)
        return None
    try:
        zef = zf.open(info)
    except NotImplementedError as exc:
        ctx.incomplete("zip-compression", "Archive member uses an unsupported compression method", {"error": _err(exc)}, where)
        return None
    except Exception as exc:
        ctx.malformed("zip-member", "Archive member cannot be opened", {"error": _err(exc)}, where)
        return None
    # The CRC is verified separately after reading: PyTorch does not check it, so a bad CRC
    # must not stop us from seeing what PyTorch would load.
    if hasattr(zef, "_expected_crc"):
        zef._expected_crc = None
    return zef


def _member_reader(ctx: _Ctx, zf: zipfile.ZipFile, info: zipfile.ZipInfo, where: dict[str, Any]):
    zef = _open_member(ctx, zf, info, where)
    if zef is None:
        return None, None, False
    cap = min(info.file_size, ctx.limits["max_decompressed_bytes"], max(0, ctx.decompress_left))
    capped = cap < info.file_size
    return _Reader(zef, cap, capped_end=capped, limits=ctx.limits, crc=True), zef, capped


def _check_crc(ctx: _Ctx, reader: _Reader, info: zipfile.ZipInfo, where: dict[str, Any], capped: bool) -> None:
    if capped or info.file_size > (64 << 20):
        return
    try:
        reader.drain()
    except Exception:
        return
    crc = (reader.crc or 0) & 0xFFFFFFFF
    if reader.tell() == info.file_size and crc != info.CRC:
        ctx.malformed(
            "zip-crc",
            "Archive member fails its CRC check (loaders that skip CRC checks, such as PyTorch, still read it)",
            {"expected_crc": f"{info.CRC:08x}", "actual_crc": f"{crc:08x}"},
            where,
        )


def _zip_pickle_member(ctx: _Ctx, zf: zipfile.ZipFile, info: zipfile.ZipInfo, where: dict[str, Any]) -> None:
    reader, zef, capped = _member_reader(ctx, zf, info, where)
    if reader is None:
        return
    with zef:
        st = _walk_pickles(ctx, reader, where)
        ctx.pickle_streams += 1
        _record_stream(ctx, st, where)
        if not st.error and not st.incomplete:
            _check_crc(ctx, reader, info, where, capped)
        ctx.decompress_left -= reader.tell()


def _zip_npy_member(ctx: _Ctx, zf: zipfile.ZipFile, info: zipfile.ZipInfo, where: dict[str, Any]) -> dict[str, Any] | None:
    reader, zef, _capped = _member_reader(ctx, zf, info, where)
    if reader is None:
        return None
    with zef:
        try:
            props = _npy_stream(ctx, reader, where)
        except Exception as exc:
            ctx.malformed("npy-member", "Archive .npy member cannot be read", {"error": _err(exc)}, where)
            props = None
        ctx.decompress_left -= reader.tell()
    return props


def _member_bytes(ctx: _Ctx, zf: zipfile.ZipFile, info: zipfile.ZipInfo, where: dict[str, Any], cap: int) -> bytes | None:
    if info.file_size > cap:
        ctx.incomplete("member-too-large", "Archive member exceeds the size cap and was not analysed", {"size": info.file_size, "cap": cap}, where)
        return None
    zef = _open_member(ctx, zf, info, where)
    if zef is None:
        return None
    try:
        with zef:
            out = zef.read(info.file_size)
    except Exception as exc:
        ctx.malformed("zip-member", "Archive member cannot be read", {"error": _err(exc)}, where)
        return None
    ctx.decompress_left -= len(out)
    return out


def _json_member(ctx: _Ctx, zf: zipfile.ZipFile, info: zipfile.ZipInfo, where: dict[str, Any]) -> Any:
    raw = _member_bytes(ctx, zf, info, where, ctx.limits["max_json_bytes"])
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception as exc:
        ctx.malformed("json-member", "Archive JSON member is not valid JSON", {"error": _err(exc)}, where)
        return None


def _zip_nested(ctx: _Ctx, zf: zipfile.ZipFile, info: zipfile.ZipInfo, depth: int, label: str) -> dict[str, Any] | None:
    where = {"member": label}
    cap = min(ctx.limits["max_nested_member_bytes"], max(0, ctx.decompress_left))
    if info.file_size > cap:
        ctx.incomplete(
            "nested-too-large", "Embedded model file exceeds the nested-analysis size cap", {"size": info.file_size, "cap": cap}, where
        )
        return None
    zef = _open_member(ctx, zf, info, where)
    if zef is None:
        return None
    with tempfile.TemporaryFile() as tmp:
        copied = 0
        try:
            with zef:
                while True:
                    chunk = zef.read(1 << 20)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > cap:
                        ctx.incomplete("nested-too-large", "Embedded model file exceeds the nested-analysis size cap", {"cap": cap}, where)
                        return None
                    tmp.write(chunk)
        except Exception as exc:
            ctx.malformed("zip-member", "Embedded model file cannot be extracted", {"error": _err(exc)}, where)
            return None
        ctx.decompress_left -= copied
        if copied == 0:
            return None
        tmp.flush()
        name = info.filename.rsplit("/", 1)[-1]
        sub = _analyze(ctx, tmp, copied, name, _effective_ext(name), depth + 1, label)
        if sub is not None:
            sub.pop("_licence", None)
        return sub


def _mar_details(ctx: _Ctx, manifest: dict[str, Any], py_files: list[str], cwhere: dict[str, Any],
                 container: str) -> dict[str, Any]:
    model = manifest.get("model") if isinstance(manifest.get("model"), dict) else {}
    out: dict[str, Any] = {}
    for key, prop in (("modelName", "mar_model_name"), ("handler", "mar_handler"), ("serializedFile", "mar_serialized_file"),
                      ("modelFile", "mar_model_file"), ("requirementsFile", "mar_requirements_file")):
        val = model.get(key)
        if isinstance(val, str) and val:
            out[prop] = val[:200]
    if isinstance(manifest.get("runtime"), str):
        out["mar_runtime"] = manifest["runtime"][:50]
    handler = out.get("mar_handler", "")
    custom_handler = handler.endswith(".py") or ":" in handler or "/" in handler
    if py_files or custom_handler:
        ctx.add(
            "ait.model.mar.handler-code",
            "TorchServe archive ships custom handler code that runs when the model is served",
            [{
                "handler": handler or None,
                "py_files": py_files[: ctx.limits["max_listed"]],
                "model_file": out.get("mar_model_file"),
                "requirements_file": out.get("mar_requirements_file"),
                **cwhere,
            }],
            disc=container,
        )
    if py_files:
        out["mar_py_files"] = py_files[: ctx.limits["max_listed"]]
    return out


# --------------------------------------------------------------------------------------------
# Keras (.keras v3 config.json, HDF5 byte search)
# --------------------------------------------------------------------------------------------


def _code_tokens(ctx: _Ctx, b64: str) -> list[str]:
    """Names in base64 Lambda bytecode, by byte search only (the bytecode is never unmarshalled)."""
    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", b64.replace("\\n", "").replace("\\r", ""))[: 8 << 20]
    cleaned = cleaned.rstrip("=")
    if len(cleaned) % 4 == 1:  # a dangling sextet cannot encode a byte
        cleaned = cleaned[:-1]
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        raw = base64.b64decode(cleaned, validate=False)
    except (binascii.Error, ValueError):
        return []
    return sorted({t.decode("ascii") for t in ctx.rules.keras_tokens if t in raw})


def _lambda_details(ctx: _Ctx, node: dict[str, Any]) -> dict[str, Any]:
    cfg = node.get("config") if isinstance(node.get("config"), dict) else {}
    d: dict[str, Any] = {"layer": str(cfg.get("name", ""))[:100]}
    fn = cfg.get("function")
    code = None
    if isinstance(fn, dict):
        fcfg = fn.get("config")
        if fn.get("class_name") == "__lambda__" and isinstance(fcfg, dict):
            code = fcfg.get("code")
            d["function_type"] = "bytecode"
        elif isinstance(fcfg, str):
            d["function_type"] = "named"
            d["function"] = f"{fn.get('module', '')}.{fcfg}"[:200]
    elif isinstance(fn, list) and fn and isinstance(fn[0], str):
        code = fn[0]
        d["function_type"] = str(cfg.get("function_type", "lambda"))[:50]
    elif isinstance(fn, str):
        d["function_type"] = "named"
        d["function"] = fn[:200]
    if isinstance(code, str):
        d["code_tokens"] = _code_tokens(ctx, code)
    return d


def _report_lambdas(ctx: _Ctx, lambdas: list[dict[str, Any]], where: dict[str, Any], found_in: str) -> None:
    if not lambdas:
        return
    tokens = sorted({t for item in lambdas for t in item.get("code_tokens", [])})
    title = f"Keras Lambda layer(s) embed arbitrary Python ({len(lambdas)})"
    over: dict[str, Any] = {}
    if tokens:
        title += f"; bytecode references {', '.join(tokens[:5])}"
        over = {"severity": "critical", "verdict": "malicious"}
    details = [{**where, "found_in": found_in, **item} for item in lambdas[: ctx.limits["max_listed"]]]
    ctx.add("ait.model.keras.lambda-layer", title, details, disc=_label(where), **over)


def _keras_targets(node: dict[str, Any]) -> list[str]:
    """Attribute names Keras resolves on `node["module"]` when deserialising this object."""
    cn = node.get("class_name")
    cfg = node.get("config")
    if cn == "function" or node.get("registered_name") == "function":
        return [cfg] if isinstance(cfg, str) and cfg else []  # {"module": m, "config": fn_name}
    return [cn] if isinstance(cn, str) and cn else []


def _keras_config(ctx: _Ctx, raw: bytes, where: dict[str, Any]) -> dict[str, Any]:
    try:
        cfg = json.loads(raw)
    except Exception as exc:
        ctx.malformed("keras-config", "Keras config.json is not valid JSON", {"error": _err(exc)}, where)
        return {}
    props: dict[str, Any] = {}
    if isinstance(cfg, dict) and isinstance(cfg.get("class_name"), str):
        props["keras_model_class"] = cfg["class_name"][:100]
    lambdas: list[dict[str, Any]] = []
    dangerous: dict[str, tuple[_Entry, str]] = {}
    stack: list[tuple[Any, int]] = [(cfg, 0)]
    visited = 0
    while stack:
        node, depth = stack.pop()
        visited += 1
        if visited > 2_000_000:
            ctx.incomplete("keras-config-size", "Keras config.json is too large to walk completely", None, where)
            break
        if isinstance(node, dict):
            if node.get("class_name") == "Lambda":
                lambdas.append(_lambda_details(ctx, node))
            module = node.get("module")
            if isinstance(module, str) and module:
                for target in _keras_targets(node):
                    verdict, entry, matched = ctx.rules.classify(module, target)
                    if verdict == "deny" and entry is not None:
                        dangerous.setdefault(f"{module}.{target}", (entry, matched))
            if depth < 512:
                stack.extend((v, depth + 1) for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list) and depth < 512:
            stack.extend((v, depth + 1) for v in node if isinstance(v, (dict, list)))
    _report_lambdas(ctx, lambdas, where, "config.json")
    for callable_, (entry, matched) in sorted(dangerous.items()):
        ctx.add(
            "ait.model.keras.dangerous-callable",
            f"Keras config references dangerous callable {callable_} ({entry.category})",
            [{"callable": callable_, "resolves_to": matched, "matched_rule": entry.label, "category": entry.category, **where}],
            disc=callable_,
        )
    props["lambda_layers"] = len(lambdas)
    return props


_LAMBDA_RE = re.compile(rb'"class_name"\s*:\s*"Lambda"')
_FUNC_B64_RE = re.compile(rb'"function"\s*:\s*\[\s*"((?:[A-Za-z0-9+/=]|\\n|\\r){8,})"')
_H5_MARKERS = (b"model_config", b"keras_version", b"training_config", b"layer_names")


def _hdf5_userblock_offset(fh, size: int) -> int | None:
    off = 512
    while off + 8 <= size and off <= (1 << 20):
        fh.seek(off)
        if fh.read(8) == _HDF5_SIG:
            return off
        off *= 2
    return None


def _analyze_hdf5(ctx: _Ctx, fh, size: int, where: dict[str, Any], sig_offset: int) -> dict[str, Any]:
    """HDF5 / Keras .h5. Heuristic: a bounded byte search of the head and tail of the file.

    Keras stores `model_config` as a JSON string attribute on the root group; HDF5 never
    compresses attributes, so the JSON is present verbatim. Configs stored beyond the searched
    regions (dense attribute storage in a huge file) are missed, which the properties record.
    """
    lim = ctx.limits
    head = min(size, lim["hdf5_head_bytes"])
    regions = [(0, head)]
    tail_start = max(head, size - lim["hdf5_tail_bytes"])
    if tail_start < size:
        regions.append((tail_start, size))
    markers: set[str] = set()
    lambda_offsets: set[int] = set()
    blobs: dict[int, bytes] = {}
    chunk, overlap = 4 << 20, 64 << 10
    for start, end in regions:
        pos = start
        while pos < end:
            fh.seek(pos)
            buf = fh.read(min(chunk + overlap, end - pos))
            if not buf:
                break
            for m in _H5_MARKERS:
                if m in buf:
                    markers.add(m.decode("ascii"))
            for mt in _LAMBDA_RE.finditer(buf):
                lambda_offsets.add(pos + mt.start())
            for mt in _FUNC_B64_RE.finditer(buf):
                blobs.setdefault(pos + mt.start(), mt.group(1)[: 8 << 20])
            pos += chunk
    keras = bool(markers & {"model_config", "keras_version", "layer_names"})
    props: dict[str, Any] = {
        "format": "keras-h5" if keras else "hdf5",
        "format_confidence": "magic",
        "detection": "bounded-byte-search",
        "searched_bytes": sum(e - s for s, e in regions),
        "keras_markers": sorted(markers),
        "lambda_layers": len(lambda_offsets),
    }
    if sig_offset:
        props["hdf5_userblock_bytes"] = sig_offset
    if lambda_offsets:
        tokens = sorted({t for b in blobs.values() for t in _code_tokens(ctx, b.decode("ascii", "replace"))})
        items = [{"offset": off, "detection": "byte-search", "code_tokens": tokens} for off in sorted(lambda_offsets)]
        _report_lambdas(ctx, items, where, "model_config")
    return props


# --------------------------------------------------------------------------------------------
# safetensors
# --------------------------------------------------------------------------------------------


_ST_DTYPE_SIZES = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E5M2": 1, "F8_E4M3": 1, "F8_E8M0": 1, "I16": 2, "U16": 2, "F16": 2,
    "BF16": 2, "I32": 4, "U32": 4, "F32": 4, "I64": 8, "U64": 8, "F64": 8, "C64": 8,
}
_LICENCE_KEYS = ("license", "licence", "modelspec.license")


def _analyze_safetensors(ctx: _Ctx, fh, size: int, where: dict[str, Any]) -> dict[str, Any]:
    lim = ctx.limits
    props: dict[str, Any] = {
        "format": "safetensors",
        "format_confidence": "magic",
        "safe_by_format": True,
        "safety_note": "safetensors holds raw tensor bytes and a JSON header only; loading it executes no code",
    }
    fh.seek(0)
    n = struct.unpack("<Q", fh.read(8))[0]
    props["header_size"] = n
    if n > lim["max_safetensors_header_bytes"] or 8 + n > size:
        ctx.malformed(
            "safetensors-header-bounds", "safetensors header length points outside the file",
            {"header_length": n, "file_size": size}, where,
        )
        return props
    if n > lim["max_safetensors_header_parse_bytes"]:
        ctx.incomplete(
            "safetensors-header-size", "safetensors header is too large to parse here; tensors were not inventoried",
            {"header_length": n, "cap": lim["max_safetensors_header_parse_bytes"]}, where,
        )
        return props
    raw = fh.read(n)
    dup: list[str] = []

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for k, _ in pairs:
            if k in seen:
                dup.append(k)
            seen.add(k)
        return dict(pairs)

    try:
        header = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_hook)
    except Exception as exc:
        ctx.malformed("safetensors-header-json", "safetensors header is not valid UTF-8 JSON", {"error": _err(exc)}, where)
        return props
    if not isinstance(header, dict):
        ctx.malformed("safetensors-header-type", "safetensors header is not a JSON object", None, where)
        return props
    problems: list[str] = []
    if dup:
        problems.append(f"duplicate keys: {', '.join(sorted(set(dup))[:5])}")
    meta = header.pop("__metadata__", None)
    if meta is not None:
        if isinstance(meta, dict):
            props["metadata"] = {str(k)[:100]: v[:500] if isinstance(v, str) else v for k, v in list(meta.items())[:50]}
            if any(not isinstance(v, str) for v in meta.values()):
                problems.append("__metadata__ values must be strings")
            lowered = {str(k).lower(): v for k, v in meta.items()}
            for key in _LICENCE_KEYS:
                val = lowered.get(key)
                if isinstance(val, str) and val.strip():
                    props["_licence"] = val.strip()[:200]
                    break
        else:
            problems.append("__metadata__ is not an object")
    data_len = size - 8 - n
    dtypes: Counter[str] = Counter()
    params = 0
    spans: list[tuple[int, int]] = []
    for name, t in header.items():
        tag = str(name)[:80]
        if not isinstance(t, dict):
            problems.append(f"{tag}: entry is not an object")
            continue
        dt, shape, off = t.get("dtype"), t.get("shape"), t.get("data_offsets")
        if not isinstance(dt, str):
            problems.append(f"{tag}: dtype missing")
            continue
        dtypes[dt] += 1
        if not (isinstance(shape, list) and all(type(x) is int and x >= 0 for x in shape)):
            problems.append(f"{tag}: invalid shape")
            continue
        if not (
            isinstance(off, list) and len(off) == 2 and all(type(x) is int for x in off) and 0 <= off[0] <= off[1] <= data_len
        ):
            problems.append(f"{tag}: data_offsets out of bounds")
            continue
        count = math.prod(shape)
        params += count
        isz = _ST_DTYPE_SIZES.get(dt)
        if isz is not None and count * isz != off[1] - off[0]:
            problems.append(f"{tag}: byte length does not match dtype x shape")
        spans.append((off[0], off[1]))
    cursor = 0
    for a, e in sorted(spans):
        if a != cursor:
            problems.append("tensor byte ranges are not contiguous (gap or overlap)")
            break
        cursor = e
    else:
        if spans and cursor != data_len:
            problems.append("tensor data does not cover the data section exactly")
    props.update(tensor_count=len(header), dtypes=dict(sorted(dtypes.items())), parameter_count=params)
    if problems:
        ctx.malformed(
            "safetensors-header-content",
            "safetensors header is inconsistent with the file (the reference loader rejects it; other parsers may not)",
            {"problems": problems[:10], "problem_count": len(problems)},
            where,
        )
    return props


# --------------------------------------------------------------------------------------------
# GGUF
# --------------------------------------------------------------------------------------------


class _Bin:
    """Bounded little-endian reader over a seekable file."""

    def __init__(self, fh, size: int) -> None:
        self.f, self.size, self.pos = fh, size, 0
        fh.seek(0)

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.size:
            raise _Malformed(f"truncated: {n} bytes needed at offset {self.pos}")
        out = self.f.read(n)
        if len(out) != n:
            raise _Malformed(f"short read at offset {self.pos}")
        self.pos += n
        return out

    def skip(self, n: int) -> None:
        if n < 0 or self.pos + n > self.size:
            raise _Malformed(f"truncated: {n} bytes needed at offset {self.pos}")
        self.f.seek(n, io.SEEK_CUR)
        self.pos += n

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]


_GGUF_SCALARS = {
    0: ("<B", 1), 1: ("<b", 1), 2: ("<H", 2), 3: ("<h", 2), 4: ("<I", 4), 5: ("<i", 4), 6: ("<f", 4),
    7: ("<?", 1), 10: ("<Q", 8), 11: ("<q", 8), 12: ("<d", 8),
}


def _gguf_value(b: _Bin, vtype: int, v1: bool, keep: bool, lim: dict[str, int], depth: int = 0) -> Any:
    scalar = _GGUF_SCALARS.get(vtype)
    if scalar is not None:
        raw = b.read(scalar[1])
        return struct.unpack(scalar[0], raw)[0] if keep else None
    if vtype == 8:  # string
        ln = b.u32() if v1 else b.u64()
        if keep and ln <= lim["max_gguf_string_store"]:
            return b.read(ln).decode("utf-8", "replace")
        b.skip(ln)
        return None
    if vtype == 9:  # array
        if depth >= 3:
            raise _Malformed("GGUF arrays nested too deeply")
        etype = b.u32()
        count = b.u32() if v1 else b.u64()
        if count > lim["max_gguf_array"]:
            raise _Malformed(f"implausible GGUF array length {count}")
        escalar = _GGUF_SCALARS.get(etype)
        kept = min(count, 32) if keep else 0
        out = [_gguf_value(b, etype, v1, True, lim, depth + 1) for _ in range(kept)]
        rest = count - kept
        if escalar is not None:
            b.skip(rest * escalar[1])
        else:
            for _ in range(rest):
                _gguf_value(b, etype, v1, False, lim, depth + 1)
        return out if keep else None
    raise _Malformed(f"unknown GGUF value type {vtype}")


def _analyze_gguf(ctx: _Ctx, fh, size: int, where: dict[str, Any]) -> dict[str, Any]:
    lim = ctx.limits
    prefix = ctx.rules.template_prefix
    props: dict[str, Any] = {"format": "gguf", "format_confidence": "magic"}
    b = _Bin(fh, size)
    general: dict[str, Any] = {}
    checked = 0
    unchecked: list[dict[str, Any]] = []
    try:
        b.read(4)
        version = b.u32()
        props["gguf_version"] = version
        if version not in (1, 2, 3):
            ctx.incomplete("gguf-version", f"Unsupported GGUF version {version}; metadata not parsed", {"version": version}, where)
            return props
        v1 = version == 1
        count = b.u32 if v1 else b.u64
        props["tensor_count"] = count()
        n_kv = count()
        props["kv_count"] = n_kv
        if n_kv > lim["max_gguf_kv"]:
            raise _Malformed(f"implausible metadata count {n_kv}")
        for _ in range(n_kv):
            klen = count()
            if klen > 65535:
                raise _Malformed("metadata key longer than 65535 bytes")
            key = b.read(klen).decode("utf-8", "replace")
            vtype = b.u32()
            if vtype == 8 and key.startswith(prefix):
                # Checked as it is read, so only one template is held at a time. One that is
                # too large or past the count cap is skipped and reported, never passed as clean.
                ln = count()
                if checked >= lim["max_gguf_templates"] or ln > lim["max_gguf_template_bytes"]:
                    b.skip(ln)
                    unchecked.append({"key": key[:200], "length": ln})
                else:
                    checked += 1
                    _check_template(ctx, key, b.read(ln).decode("utf-8", "replace"), where)
                continue
            keep = key.startswith("general.") and len(general) < 64
            value = _gguf_value(b, vtype, v1, keep, lim)
            if keep:
                general[key] = value
    except (_Malformed, struct.error, OverflowError) as exc:
        ctx.malformed("gguf-parse", "GGUF metadata is truncated or malformed", {"error": _err(exc), "offset": b.pos}, where)
    if unchecked:
        ctx.incomplete(
            "gguf-template-unchecked",
            "GGUF chat template was not checked (too large, or too many templates)",
            {"templates": unchecked[: lim["max_listed"]], "count": len(unchecked),
             "max_template_bytes": lim["max_gguf_template_bytes"], "max_templates": lim["max_gguf_templates"]},
            where,
        )
    if general:
        props["metadata"] = general
        if isinstance(general.get("general.architecture"), str):
            props["architecture"] = general["general.architecture"][:100]
        lic = general.get("general.license")
        if isinstance(lic, str) and lic.strip():
            props["_licence"] = lic.strip()[:200]
    props["chat_template_present"] = bool(checked or unchecked)
    return props


def _check_template(ctx: _Ctx, key: str, tpl: str, where: dict[str, Any]) -> None:
    hits: list[str] = []
    first: int | None = None
    for mid, rx in ctx.rules.ssti:
        m = rx.search(tpl)
        if m:
            hits.append(mid)
            first = m.start() if first is None else min(first, m.start())
    if not hits or first is None:
        return
    excerpt = tpl[max(0, first - 60): first + 100].replace("\n", "\\n")
    ctx.add(
        "ait.model.gguf.chat-template-ssti",
        f"GGUF chat template contains template-injection markers ({', '.join(hits[:4])})",
        [{"key": key, "markers": hits, "excerpt": excerpt, "template_length": len(tpl), **where}],
        disc=key,
    )


# --------------------------------------------------------------------------------------------
# ONNX (minimal streaming protobuf decoding of ModelProto)
# --------------------------------------------------------------------------------------------


class _PB:
    def __init__(self, fh, size: int, budget: int) -> None:
        self.f, self.size, self.budget = fh, size, budget

    def _varint_at(self, pos: int) -> tuple[int, int]:
        self.f.seek(pos)
        buf = self.f.read(10)
        result = shift = 0
        for i, byte in enumerate(buf):
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result, pos + i + 1
            shift += 7
        raise _Malformed(f"truncated or over-long varint at offset {pos}")

    def fields(self, start: int, end: int):
        """Yield (field, wire_type, value); LEN fields yield their (offset, length) span."""
        pos = start
        while pos < end:
            self.budget -= 1
            if self.budget < 0:
                raise _Incomplete("ONNX field budget exhausted")
            key, pos = self._varint_at(pos)
            fno, wt = key >> 3, key & 7
            if fno == 0:
                raise _Malformed(f"invalid protobuf field number 0 at offset {pos}")
            if wt == 0:
                val, pos = self._varint_at(pos)
                if pos > end:
                    raise _Malformed("varint overruns its message")
                yield fno, 0, val
            elif wt == 2:
                ln, pos = self._varint_at(pos)
                if pos + ln > end:
                    raise _Malformed(f"field {fno} (length {ln}) overruns its message at offset {pos}")
                yield fno, 2, (pos, ln)
                pos += ln
            elif wt in (1, 5):
                pos += 8 if wt == 1 else 4
                if pos > end:
                    raise _Malformed("fixed-width field overruns its message")
                yield fno, wt, None
            else:
                raise _Malformed(f"unsupported protobuf wire type {wt} at offset {pos}")

    def text(self, span: tuple[int, int], cap: int = 512) -> str:
        self.f.seek(span[0])
        return self.f.read(min(span[1], cap)).decode("utf-8", "replace")


class _OnnxStats:
    def __init__(self) -> None:
        self.nodes = 0
        self.ops: dict[str, Counter[str]] = {}
        self.function_domains: set[str] = set()
        self.initializers = 0
        self.external: list[tuple[str, str]] = []
        self.opsets: list[tuple[str, int | None]] = []
        self.metadata: dict[str, str] = {}


def _onnx_kv(pb: _PB, span: tuple[int, int]) -> tuple[str, str]:
    key = value = ""
    for fno, wt, v in pb.fields(span[0], span[0] + span[1]):
        if wt == 2 and fno == 1:
            key = pb.text(v, 200)
        elif wt == 2 and fno == 2:
            value = pb.text(v, 1024)
    return key, value


def _onnx_tensor(pb: _PB, span: tuple[int, int], st: _OnnxStats) -> None:
    name = ""
    location = None
    for fno, wt, v in pb.fields(span[0], span[0] + span[1]):
        if fno == 8 and wt == 2:
            name = pb.text(v, 200)
        elif fno == 13 and wt == 2:
            k, val = _onnx_kv(pb, v)
            if k == "location":
                location = val
    if location is not None and len(st.external) < 100_000:
        st.external.append((name, location))


def _onnx_sparse(pb: _PB, span: tuple[int, int], st: _OnnxStats) -> None:
    for fno, wt, v in pb.fields(span[0], span[0] + span[1]):
        if wt == 2 and fno in (1, 2):
            _onnx_tensor(pb, v, st)


def _onnx_node(pb: _PB, span: tuple[int, int], st: _OnnxStats, depth: int, lim: dict[str, int]) -> None:
    st.nodes += 1
    if st.nodes > lim["max_onnx_nodes"]:
        raise _Incomplete("ONNX node cap reached")
    op = dom = ""
    attrs = []
    for fno, wt, v in pb.fields(span[0], span[0] + span[1]):
        if wt != 2:
            continue
        if fno == 4:
            op = pb.text(v, 200)
        elif fno == 7:
            dom = pb.text(v, 200)
        elif fno == 5:
            attrs.append(v)
    for a in attrs:
        _onnx_attr(pb, a, st, depth, lim)
    if dom not in st.ops and len(st.ops) >= 200:
        dom = "<other>"
    counter = st.ops.setdefault(dom, Counter())
    if op not in counter and len(counter) >= 200:
        op = "<other>"
    counter[op] += 1


def _onnx_attr(pb: _PB, span: tuple[int, int], st: _OnnxStats, depth: int, lim: dict[str, int]) -> None:
    for fno, wt, v in pb.fields(span[0], span[0] + span[1]):
        if wt != 2:
            continue
        if fno in (5, 10):  # t, tensors
            _onnx_tensor(pb, v, st)
        elif fno in (6, 11):  # g, graphs (If/Loop/Scan bodies)
            _onnx_graph(pb, v, st, depth + 1, lim)
        elif fno in (22, 23):  # sparse_tensor(s)
            _onnx_sparse(pb, v, st)


def _onnx_graph(pb: _PB, span: tuple[int, int], st: _OnnxStats, depth: int, lim: dict[str, int]) -> None:
    if depth > lim["max_onnx_depth"]:
        raise _Incomplete("ONNX subgraphs nested beyond the depth cap")
    for fno, wt, v in pb.fields(span[0], span[0] + span[1]):
        if wt != 2:
            continue
        if fno == 1:
            _onnx_node(pb, v, st, depth, lim)
        elif fno == 5:
            st.initializers += 1
            _onnx_tensor(pb, v, st)
        elif fno == 15:
            _onnx_sparse(pb, v, st)


def _onnx_function(pb: _PB, span: tuple[int, int], st: _OnnxStats, lim: dict[str, int]) -> None:
    for fno, wt, v in pb.fields(span[0], span[0] + span[1]):
        if wt != 2:
            continue
        if fno == 10:
            st.function_domains.add(pb.text(v, 200))
        elif fno == 7:
            _onnx_node(pb, v, st, 1, lim)


def _onnx_model(pb: _PB, st: _OnnxStats, info: dict[str, Any], lim: dict[str, int]) -> None:
    for fno, wt, v in pb.fields(0, pb.size):
        if wt == 0:
            if fno == 1:
                info["ir_version"] = v
            elif fno == 5:
                info["model_version"] = v
        elif wt == 2:
            if fno == 2:
                info["producer_name"] = pb.text(v, 200)
            elif fno == 3:
                info["producer_version"] = pb.text(v, 100)
            elif fno == 4:
                info["model_domain"] = pb.text(v, 200)
            elif fno == 7:
                info["graph"] = True
                _onnx_graph(pb, v, st, 0, lim)
            elif fno == 8:
                dom, ver = "", None
                for f2, w2, v2 in pb.fields(v[0], v[0] + v[1]):
                    if f2 == 1 and w2 == 2:
                        dom = pb.text(v2, 200)
                    elif f2 == 2 and w2 == 0:
                        ver = v2
                st.opsets.append((dom, ver))
            elif fno == 14:
                k, val = _onnx_kv(pb, v)
                if len(st.metadata) < 32:
                    st.metadata[k[:100]] = val[:300]
            elif fno == 20:  # training_info: initialization / algorithm graphs
                for f2, w2, v2 in pb.fields(v[0], v[0] + v[1]):
                    if w2 == 2 and f2 in (1, 2):
                        _onnx_graph(pb, v2, st, 0, lim)
            elif fno == 25:
                _onnx_function(pb, v, st, lim)


def _analyze_onnx(ctx: _Ctx, fh, size: int, where: dict[str, Any]) -> dict[str, Any]:
    lim = ctx.limits
    pb = _PB(fh, size, lim["max_onnx_fields"])
    st = _OnnxStats()
    model: dict[str, Any] = {}
    failed = False
    try:
        _onnx_model(pb, st, model, lim)
    except _Incomplete as exc:
        ctx.incomplete("onnx-cap", "ONNX model was only partially analysed", {"reason": str(exc)}, where)
    except Exception as exc:
        failed = True
        ctx.malformed("onnx-parse", "ONNX protobuf is truncated or malformed", {"error": _err(exc)}, where)
    if model.get("ir_version") is None and not model.get("graph") and not failed:
        ctx.malformed("onnx-structure", "Not an ONNX ModelProto (no ir_version and no graph)", None, where)
    props: dict[str, Any] = {"format": "onnx", "format_confidence": "structure"}
    for key in ("ir_version", "producer_name", "producer_version", "model_version", "model_domain"):
        if model.get(key) not in (None, ""):
            props[key] = model[key]
    props["opset_import"] = [{"domain": d or "ai.onnx", "version": v} for d, v in st.opsets[:50]]
    props["node_count"] = st.nodes
    props["op_domains"] = sorted((d or "ai.onnx") for d in st.ops)
    props["initializer_count"] = st.initializers
    if st.function_domains:
        props["function_domains"] = sorted(st.function_domains)[:50]
    if st.metadata:
        props["metadata"] = st.metadata
        for k, v in st.metadata.items():
            if k.lower() in ("license", "licence") and v.strip():
                props["_licence"] = v.strip()[:200]
                break
    if st.external:
        props["external_data_files"] = sorted({loc[:300] for _, loc in st.external})[: lim["max_listed"]]

    versions = {d: v for d, v in st.opsets}
    for dom, ops in sorted(st.ops.items()):
        if dom in ctx.rules.onnx_standard or dom in st.function_domains:
            continue
        vendor = ctx.rules.onnx_vendor.get(dom)
        detail = {
            "domain": dom,
            "op_types": [op for op, _ in ops.most_common(20)],
            "node_count": sum(ops.values()),
            "opset_version": versions.get(dom),
            "note": vendor,
            **where,
        }
        if vendor:
            ctx.add("ait.model.onnx.vendor-op-domain", f"ONNX model uses runtime-vendor operators from '{dom}'", [detail], disc=dom)
        else:
            ctx.add("ait.model.onnx.custom-op-domain", f"ONNX model uses custom operators from domain '{dom}'", [detail], disc=dom)
    unsafe = [(t, loc) for t, loc in st.external if _unsafe_path(loc)]
    if unsafe:
        ctx.add(
            "ait.model.onnx.external-data-path",
            f"ONNX external-data locations escape the model directory ({len(unsafe)})",
            [{"tensor": t, "location": loc[:300], **where} for t, loc in unsafe[: lim["max_listed"]]],
            disc=_label(where),
        )
    return props


# --------------------------------------------------------------------------------------------
# TFLite (inventory only)
# --------------------------------------------------------------------------------------------


def _unpack(fmt: str, buf: bytes, off: int) -> int:
    if off < 0:
        raise ValueError("negative offset")
    return struct.unpack_from(fmt, buf, off)[0]


def _tflite_info(fh, size: int) -> dict[str, Any]:
    fh.seek(0)
    head = fh.read(min(size, 1 << 20))
    info: dict[str, Any] = {"format": "tflite", "format_confidence": "magic", "flatbuffer_identifier": "TFL3"}
    try:
        root = _unpack("<I", head, 0)
        vtable = root - _unpack("<i", head, root)
        vt_size = _unpack("<H", head, vtable)

        def field(i: int) -> int:
            if 4 + 2 * i + 2 > vt_size:
                return 0
            return _unpack("<H", head, vtable + 4 + 2 * i)

        off = field(0)  # Model.version
        if off:
            info["schema_version"] = _unpack("<I", head, root + off)
        off = field(3)  # Model.description
        if off:
            s = root + off + _unpack("<I", head, root + off)
            n = _unpack("<I", head, s)
            info["description"] = head[s + 4: s + 4 + min(n, 200)].decode("utf-8", "replace")
    except (struct.error, ValueError):
        pass  # inventory only; the identifier is enough
    return info


# --------------------------------------------------------------------------------------------
# JSON-safety of properties
# --------------------------------------------------------------------------------------------


def _jsonable(value: Any, depth: int = 0) -> Any:
    if isinstance(value, (dict, list, tuple, set, frozenset)) and depth > 8:
        return f"<nested {type(value).__name__}>"
    if isinstance(value, dict):
        return {str(k)[:200]: _jsonable(v, depth + 1) for k, v in itertools.islice(value.items(), 200)}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str)[:200] if isinstance(value, (set, frozenset)) else list(value[:200])
        return [_jsonable(v, depth + 1) for v in items]
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, (bytes, bytearray)):
        return value[:64].hex()
    if isinstance(value, int) and not isinstance(value, bool) and value.bit_length() > 256:
        return f"<int of {value.bit_length()} bits>"  # str() of a huge int is refused by Python
    if value is None or isinstance(value, (bool, int, str)):
        return value[:2000] if isinstance(value, str) else value
    return str(value)[:200]
