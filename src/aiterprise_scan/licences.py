"""Model-licence verdicts and conflict detection (design doc 13 C25, §4.3, §4.5, §5.3).

Three steps:

1. `discover_model_refs` finds Hugging Face model / dataset references in code, notebooks,
   configs and markdown, plus local model / dataset cards (README.md YAML front matter).
2. `verdict_for` maps a licence tag (or, failing that, a model id) to a verdict from the
   first-party matrix in `data/ait/licence-verdicts.json`. Every verdict cites the licence text
   it was checked against (`text_url`, `checked_at`, `verified`).
3. `judge_licences` turns verdicts into findings against the project's `use_context` and the
   policy allow / deny lists.

Verdicts are advisory, not legal advice. Hugging Face tags are hints: an inferred verdict says so
(`inferred=True`, lower confidence) and the licence text is always linked.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from . import data, miniyaml, scancache, sources
from .callargs import KWARG_RE as _KWARG_RE
from .callargs import call_args as _call_args
from .callargs import line_at as _line_at
from .callargs import literal as _literal
from .model import OWASP_SUPPLY_CHAIN, Component, Evidence, Finding, Location
from .textio import TooLarge, read_text
from .walk import rel_posix

__all__ = [
    "LicenceVerdict",
    "USE_CONTEXTS",
    "verdict_for",
    "discover_model_refs",
    "judge_licences",
]

DATA_FILE = "licence-verdicts.json"
ADVISORY = "not legal advice"
USE_CONTEXTS = ("commercial", "internal", "research", "non-profit")
_COMMERCIAL_LIKE = {"commercial", "internal"}
JUDGED_CTYPES = ("model", "dataset", "model-file")  # the component types judge_licences looks at
# Declared values that say "no usable licence id here" — fall back to name inference.
_PLACEHOLDERS = {"", "other", "unknown", "none", "noassertion", "n/a", "na", "null", "unspecified"}


# ---------------------------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------------------------


@dataclass
class LicenceVerdict:
    licence_id: str
    verdict_id: str
    name: str
    commercial_ok: bool | str  # True | False | "conditional"
    mau_threshold: int | None
    attribution_required: bool
    attribution_text: str
    field_of_use: list[str]
    flow_down: bool
    redistribution_ok: bool
    share_alike: bool
    no_derivatives: bool
    text_url: str
    verified: bool
    checked_at: str
    notes: str
    inferred: bool = False
    basis: str = ""
    confidence: int = 90
    kind: str = "model"  # model | data | software
    commercial_conditions: list[str] = field(default_factory=list)
    condition_label: str = ""
    aup_url: str | None = None
    standard_permissive: bool = False
    remediation: str = ""
    also: list[str] = field(default_factory=list)  # further licences that bind (e.g. a distill's base)

    @property
    def base_verdict_id(self) -> str:
        """`llama3-community-v1` -> `llama3-community` (what a policy file names)."""
        return re.sub(r"-v\d+$", "", self.verdict_id)

    @property
    def tags(self) -> list[str]:
        """Category names a policy can allow / deny (e.g. `non-commercial-only`, `no-derivative`)."""
        out: list[str] = []
        if self.commercial_ok is False:
            out += ["non-commercial", "non-commercial-only"]
        if self.commercial_ok == "conditional":
            out.append("conditional-commercial")
        if self.mau_threshold:
            out.append("mau-threshold")
        if self.no_derivatives:
            out += ["no-derivative", "no-derivatives"]
        if self.share_alike:
            out += ["share-alike", "copyleft-data" if self.kind == "data" else "copyleft"]
        if self.field_of_use:
            out.append("field-of-use")
        if self.flow_down:
            out.append("flow-down")
        if self.attribution_required:
            out.append("attribution")
        if self.standard_permissive:
            out.append("permissive")
        return out

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["base_verdict_id"] = self.base_verdict_id
        d["tags"] = self.tags
        return d


@dataclass
class _Rule:
    rule_id: str
    regex: re.Pattern[str]
    licence: str | None
    confidence: int
    also: list[str]
    evidence: str


@dataclass
class _Db:
    licences: dict[str, dict[str, Any]]
    aliases: dict[str, str]
    rules: list[_Rule]
    reverse_aliases: dict[str, set[str]]


def _norm(value: str) -> str:
    s = str(value).strip().strip("\"'").strip().lower()
    for prefix in ("license:", "licence:", "licenseref-"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return re.sub(r"[\s,]+", "-", s).strip("-")


@lru_cache(maxsize=1)
def _db() -> _Db:
    raw = data.load(DATA_FILE)
    licences = {_norm(k): v for k, v in raw["licences"].items()}
    aliases = {_norm(k): _norm(v) for k, v in raw.get("aliases", {}).items()}
    reverse: dict[str, set[str]] = {}
    for alias, target in aliases.items():
        reverse.setdefault(target, set()).add(alias)
    rules = [
        _Rule(
            rule_id=r["id"],
            regex=re.compile(r["match"]),
            licence=_norm(r["licence"]) if r.get("licence") else None,
            confidence=int(r.get("confidence", 60)),
            also=[_norm(a) for a in r.get("also", [])],
            evidence=r.get("evidence", ""),
        )
        for r in raw.get("inference", [])
    ]
    return _Db(licences, aliases, rules, reverse)


def _resolve(licence: str | None) -> str | None:
    if not licence:
        return None
    key = _norm(licence)
    db = _db()
    if key in db.licences:
        return key
    target = db.aliases.get(key)
    return target if target in db.licences else None


def _make(key: str, *, inferred: bool, basis: str, confidence: int | None = None) -> LicenceVerdict:
    e = _db().licences[key]
    conf = int(e.get("confidence", 90))
    if confidence is not None:
        conf = min(conf, confidence)
    verified = bool(e.get("verified", False))
    if not verified:
        conf = min(conf, 50)
    return LicenceVerdict(
        licence_id=key,
        verdict_id=e["verdict_id"],
        name=e.get("name", key),
        commercial_ok=e.get("commercial_ok", "conditional"),
        mau_threshold=e.get("mau_threshold"),
        attribution_required=bool(e.get("attribution_required", False)),
        attribution_text=e.get("attribution_text", ""),
        field_of_use=list(e.get("field_of_use", [])),
        flow_down=bool(e.get("flow_down", False)),
        redistribution_ok=bool(e.get("redistribution_ok", True)),
        share_alike=bool(e.get("share_alike", False)),
        no_derivatives=bool(e.get("no_derivatives", False)),
        text_url=e.get("text_url", ""),
        verified=verified,
        checked_at=e.get("checked_at", ""),
        notes=e.get("notes", ""),
        inferred=inferred,
        basis=basis,
        confidence=conf,
        kind=e.get("kind", "model"),
        commercial_conditions=list(e.get("commercial_conditions", [])),
        condition_label=e.get("condition_label", ""),
        aup_url=e.get("aup_url"),
        standard_permissive=bool(e.get("standard_permissive", False)),
        remediation=e.get("remediation", ""),
    )


_ID_PREFIXES = ("hf://", "https://huggingface.co/", "http://huggingface.co/", "https://hf.co/")


def _infer(model_name: str) -> LicenceVerdict | None:
    low = model_name.strip().lower()
    for prefix in _ID_PREFIXES:
        if low.startswith(prefix):
            low = low[len(prefix):]
    db = _db()
    for rule in db.rules:
        if not rule.regex.search(low):
            continue
        if rule.licence is None or rule.licence not in db.licences:
            return None  # a known "licence not established" pattern: stop, do not guess
        v = _make(
            rule.licence,
            inferred=True,
            basis=f"inferred from model id {model_name!r} (rule {rule.rule_id}: {rule.evidence})",
            confidence=rule.confidence,
        )
        v.also = [a for a in rule.also if a in db.licences]
        return v
    return None


def verdict_for(licence: str | None, model_name: str | None = None) -> LicenceVerdict | None:
    """Verdict for a declared licence tag, else one inferred from a Hugging Face model id.

    A declared tag always wins. Placeholder tags (`other`, `unknown`, empty) fall back to the
    model id. A declared tag that is not in the matrix returns None (unknown), because a name
    guess must not override what the publisher declared.
    """
    if licence is not None and not isinstance(licence, str):
        licence = str(licence)
    key = _resolve(licence)
    if key:
        return _make(key, inferred=False, basis=f"declared licence {licence!r}")
    if licence and _norm(licence) not in _PLACEHOLDERS:
        return None
    if model_name:
        return _infer(model_name)
    return None


# ---------------------------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------------------------

_PY_SUFFIXES = {".py", ".pyi", ".pyw"}
_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
_TEXT_SUFFIXES = {".md", ".mdx", ".rst", ".txt", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env"}
_URL_MAX_BYTES = 4 * 1024 * 1024

# call name -> (what it references, keyword names for the id, positional index of the id)
_CALLS: dict[str, tuple[str, tuple[str, ...], int]] = {
    "from_pretrained": ("model", ("pretrained_model_name_or_path", "model_id"), 0),
    "pipeline": ("model", ("model",), 1),
    "hf_hub_download": ("repo", ("repo_id",), 0),
    "snapshot_download": ("repo", ("repo_id",), 0),
    "SentenceTransformer": ("model", ("model_name_or_path", "model_name"), 0),
    "CrossEncoder": ("model", ("model_name", "model_name_or_path"), 0),
    "load_dataset": ("dataset", ("path",), 0),
}
_CALL_RE = re.compile(r"\b(" + "|".join(_CALLS) + r")\s*\(")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HF_URL_RE = re.compile(r"https?://(?:www\.)?(?:huggingface\.co|hf\.co)/([A-Za-z0-9][\w.\-/@]*)")
_HF_PROTO_RE = re.compile(r"(?<![\w/])hf://([A-Za-z0-9][\w.\-/@]*)")

_FILE_EXTS = (
    ".bin", ".pt", ".pth", ".ckpt", ".safetensors", ".gguf", ".onnx", ".json", ".txt", ".csv",
    ".tsv", ".parquet", ".jsonl", ".h5", ".pkl", ".zip", ".tar", ".gz", ".yaml", ".yml", ".py",
    ".arrow", ".msgpack", ".model",
)
_LOCAL_DIRS = {
    "models", "model", "data", "datasets", "dataset", "output", "outputs", "checkpoints",
    "checkpoint", "ckpt", "ckpts", "runs", "run", "tmp", "temp", "src", "assets", "weights",
    "artifacts", "saved_models", "pretrained", "cache", "local", "results", "exports", "export",
    "adapters", "logs",
}
_LOCAL_PREFIXES = (
    "checkpoint", "output", "result", "tmp", "temp", "run-", "run_", "runs", "saved", "my-", "my_",
    "local", "models", "model-", "model_", "final", "best", "trained", "finetuned", "fine-tuned",
)
_DATASET_BUILDERS = {
    "csv", "json", "parquet", "text", "arrow", "pandas", "imagefolder", "audiofolder",
    "videofolder", "webdataset", "sql", "generator", "xml", "spark", "data", "dataset", "datasets",
    "train", "test", "local", "files",
}
_URL_RESERVED = {
    "docs", "blog", "models", "api", "papers", "learn", "join", "login", "settings",
    "organizations", "new", "new-dataset", "new-space", "pricing", "tasks", "collections", "chat",
    "posts", "enterprise", "inference-endpoints", "inference-api", "terms-of-service", "privacy",
    "changelog", "pro", "support", "search", "notifications", "static", "front", "avatars",
    "oauth", "billing", "course", "welcome", "brand", "jobs", "careers", "security", "storage",
    "deploy", "integrations", "mcp", "agents", "transformers", "status", "contact", "faq",
    "classroom", "academia", "legal", "code-of-conduct", "content-guidelines", "philosophy",
    "sitemap", "spaces", "hub", "user", "upload",
}
_URL_ACTIONS = {"resolve", "blob", "tree", "raw", "commit", "commits", "discussions", "files", "edit"}

_MODEL_CARD_KEYS = {"base_model", "pipeline_tag", "library_name", "model-index", "model_name", "base_model_relation"}
_DATASET_CARD_KEYS = {
    "task_categories", "dataset_info", "configs", "size_categories", "task_ids",
    "annotations_creators", "language_creators", "source_datasets", "multilinguality", "pretty_name",
}


@dataclass
class _Ref:
    hf_id: str
    repo_type: str  # model | dataset
    line: int | None
    revision: str | None = None


def _valid_id(value: str, root: Path | None, *, allow_single: bool, dataset: bool = False) -> bool:
    v = value.strip()
    if not v or len(v) > 200 or v != value:
        return False
    if any(c in v for c in " \t\n\\{}$%<>|*?\"'`,;:()[]=+!#&^~"):
        return False
    if v.startswith((".", "/", "-", "_")):
        return False
    parts = v.split("/")
    if len(parts) > 2:
        return False
    for p in parts:
        if len(p) > 96 or not _SEGMENT_RE.match(p) or p.endswith((".", "-")):
            return False
    if parts[-1].lower().endswith(_FILE_EXTS):
        return False
    low = v.lower()
    if len(parts) == 2:
        if parts[0].lower() in _LOCAL_DIRS:
            return False
    else:
        if not allow_single:
            return False
        if dataset:
            if low in _DATASET_BUILDERS:
                return False
        elif not re.search(r"[-\d]", low):
            return False
        if low.startswith(_LOCAL_PREFIXES):
            return False
    if root is not None and _is_local_dir(root, v):
        return False  # it is a local path that happens to look like an id
    return True


def _scan_calls(text: str, root: Path | None, *, python: bool) -> list[_Ref]:
    if not any(name in text for name in _CALLS):
        return []  # the regex needs one of the call names: most files have none
    refs: list[_Ref] = []
    comment = "#" if python else "//"
    for m in _CALL_RE.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        prefix = text[line_start:m.start()]
        if prefix.lstrip().startswith(comment) or re.search(r"\b(def|class|function)\s+$", prefix):
            continue
        what, kw_names, pos_index = _CALLS[m.group(1)]
        args = _call_args(text, m.end())
        if not args:
            continue
        positional: list[tuple[str, int]] = []
        kwargs: dict[str, tuple[str, int]] = {}
        for arg, off in args:
            km = _KWARG_RE.match(arg.strip())
            if km:
                lead = len(arg) - len(arg.lstrip())
                kwargs[km.group(1)] = (km.group(2), off + lead + km.start(2))
            elif not kwargs:
                positional.append((arg, off))
        raw = next((kwargs[k] for k in kw_names if k in kwargs), None)
        if raw is None and len(positional) > pos_index:
            raw = positional[pos_index]
        if raw is None:
            continue
        lit = _literal(*raw)
        if lit is None:
            continue  # a variable, f-string or expression: not a static reference
        value, value_off = lit
        repo_type = "dataset" if what == "dataset" else "model"
        if what == "repo" and "repo_type" in kwargs:
            rt = _literal(*kwargs["repo_type"])
            if rt is None:
                continue
            if rt[0] == "space":
                continue
            repo_type = "dataset" if rt[0] == "dataset" else "model"
        if not _valid_id(value, root, allow_single=True, dataset=repo_type == "dataset"):
            continue
        revision = None
        if "revision" in kwargs:
            rv = _literal(*kwargs["revision"])
            if rv and rv[0].strip():
                revision = rv[0].strip()
        refs.append(_Ref(value, repo_type, _line_at(text, value_off), revision))
    return refs


def _parse_hub_path(path: str, *, proto: bool) -> tuple[str, str, str | None] | None:
    """`org/name/...` (optionally `datasets/…`) -> (hf_id, repo_type, revision)."""
    segs = path.split("/")
    repo_type = "model"
    if segs and segs[0] == "datasets":
        repo_type = "dataset"
        segs = segs[1:]
    if not segs or not segs[0] or segs[0] in _URL_RESERVED or (segs[0] == "spaces"):
        return None
    if len(segs) < 2 or not segs[1] or segs[1] in _URL_ACTIONS:
        return None  # org pages and single-segment URLs are not reliable references
    org, name = segs[0], segs[1]
    revision = None
    if "@" in name:
        name, _, revision = name.partition("@")
        if not proto:
            revision = None
    if "@" in org:
        return None
    name = name.rstrip(".")
    if name.endswith(".git"):
        name = name[:-4]
    return f"{org}/{name}", repo_type, (revision or None)


_DOC_FILE_RE = re.compile(
    r"/(?:blob|raw|resolve)/[^/]+/(?:.*/)?(?:LICEN[CS]E|NOTICE|README|USE_POLICY|COPYING)[^/]*$"
    r"|/(?:blob|raw|resolve)/[^/]+/(?:.*/)?[^/]+\.(?:md|mdx|rst)$",
    re.I,
)


def _is_doc_citation(hub_path: str) -> bool:
    """A link to a repo's LICENSE / README / NOTICE cites its terms; it is not a use of the model."""
    return bool(_DOC_FILE_RE.search(hub_path.rstrip(".,;:)]}>\"'")))


def _scan_urls(text: str) -> list[_Ref]:
    refs: list[_Ref] = []
    for regex, proto, needles in ((_HF_URL_RE, False, ("huggingface.co", "hf.co")), (_HF_PROTO_RE, True, ("hf://",))):
        if not any(n in text for n in needles):
            continue  # each regex needs its host or scheme literally
        for m in regex.finditer(text):
            if _is_doc_citation(m.group(1)):
                continue
            parsed = _parse_hub_path(m.group(1), proto=proto)
            if not parsed:
                continue
            hf_id, repo_type, revision = parsed
            if not _valid_id(hf_id, None, allow_single=False):
                continue
            refs.append(_Ref(hf_id, repo_type, _line_at(text, m.start()), revision))
    return refs


def _notebook_refs(raw: str, root: Path | None) -> list[_Ref]:
    try:
        nb = json.loads(raw)
    except ValueError:
        return []
    cells = nb.get("cells") if isinstance(nb, dict) else None
    if not isinstance(cells, list):
        return []
    refs: list[_Ref] = []
    cursor = 0
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        src = cell.get("source", "")
        if isinstance(src, list):
            src = "".join(s for s in src if isinstance(s, str))
        if not isinstance(src, str) or not src:
            continue
        for ref in _scan_calls(src, root, python=True):
            line = None
            for quote in ('"', "'"):
                needle = json.dumps(f"{quote}{ref.hf_id}{quote}")[1:-1]
                idx = raw.find(needle, cursor)
                if idx < 0:
                    idx = raw.find(needle)
                if idx >= 0:
                    line = _line_at(raw, idx)
                    cursor = idx + 1
                    break
            refs.append(_Ref(ref.hf_id, ref.repo_type, line, ref.revision))
    return refs


def _front_matter(text: str) -> tuple[Any, str] | None:
    body = text.lstrip("﻿")
    lines = body.replace("\r\n", "\n").split("\n")
    if not lines or lines[0].strip() != "---":
        return None
    for i in range(1, min(len(lines), 2000)):
        if lines[i].strip() in ("---", "..."):
            yaml_text = "\n".join(lines[1:i])
            try:
                return miniyaml.load(yaml_text), yaml_text
            except (miniyaml.YAMLError, ValueError, IndexError):
                return None
    return None


def _first_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        for v in value:
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def _card_component(path: Path, root: Path, text: str) -> Component | None:
    parsed = _front_matter(text)
    if not parsed:
        return None
    meta, yaml_text = parsed
    if not isinstance(meta, dict):
        return None
    keys = set(meta)
    if "license" not in keys and "license_name" not in keys:
        return None
    is_model = bool(keys & _MODEL_CARD_KEYS)
    is_dataset = bool(keys & _DATASET_CARD_KEYS) and not is_model
    if not (is_model or is_dataset):
        return None
    declared = _first_str(meta.get("license"))
    licence_name = _first_str(meta.get("license_name"))
    licence = declared
    if licence_name and (declared is None or _norm(declared) in _PLACEHOLDERS):
        licence = licence_name
    rel = rel_posix(path, root)
    name = None
    if is_model:
        name = _first_str(meta.get("model_name"))
        mi = meta.get("model-index")
        if not name and isinstance(mi, list) and mi and isinstance(mi[0], dict):
            name = _first_str(mi[0].get("name"))
    if not name:
        name = path.parent.name if path.parent != root else ""
        if not name:
            try:
                name = root.resolve().name
            except OSError:
                name = root.name
        name = name or "model-card"
    m = re.search(r"(?m)^license(_name)?\s*:", yaml_text)
    line = _line_at(yaml_text, m.start()) + 1 if m else 1
    props: dict[str, Any] = {"card": rel, "repo_type": "dataset" if is_dataset else "model"}
    if declared:
        props["license_declared"] = declared
    for key in ("license_name", "license_link", "pipeline_tag", "library_name", "base_model_relation"):
        val = meta.get(key)
        if isinstance(val, (str, int)) and str(val).strip():
            props[key] = str(val).strip()
    base = meta.get("base_model")
    if isinstance(base, str) and base.strip():
        props["base_model"] = base.strip()
    elif isinstance(base, list):
        bases = [b.strip() for b in base if isinstance(b, str) and b.strip()]
        if bases:
            props["base_model"] = bases if len(bases) > 1 else bases[0]
    ds = meta.get("datasets")
    if isinstance(ds, list):
        names = [d for d in ds if isinstance(d, str)]
        if names:
            props["datasets"] = names
    return Component(
        name=name,
        ctype="dataset" if is_dataset else "model",
        ecosystem="huggingface" if (is_model and "/" in name) else None,
        locations=[Location(rel, line)],
        licence=licence,
        ai=True,
        source="model-card",
        properties=props,
    )


def _file_refs(text: str, variant: str) -> list[list]:
    """A file's references as [hf_id, repo_type, line, revision, in code], before the check that
    an id in code is not a folder of the scanned tree: that check reads the disk, so it is made
    on every scan, while this list is kept between scans (`scancache`). `variant`: "py", "js" or
    "" (a text file: links only)."""
    refs = [[r.hf_id, r.repo_type, r.line, r.revision, True]
            for r in (_scan_calls(text, None, python=variant == "py") if variant else [])]
    return refs + [[r.hf_id, r.repo_type, r.line, r.revision, False] for r in _scan_urls(text)]


def _is_local_dir(root: Path, value: str) -> bool:
    """`_valid_id`'s last check, the only one that reads the disk."""
    try:
        return (root / value).exists()
    except OSError:
        return False


def discover_model_refs(root: Path, files: list[Path]) -> list[Component]:
    """Hugging Face model / dataset references and local model / dataset cards."""
    root = Path(root)
    merged: dict[tuple, Component] = {}
    order: list[tuple] = []

    def add(comp: Component, key: tuple) -> None:
        existing = merged.get(key)
        if existing is None:
            merged[key] = comp
            order.append(key)
            return
        for loc in comp.locations:
            existing.add_location(loc)

    for f in files:
        path = Path(f)
        if not path.is_absolute():
            path = root / path
        suffix = path.suffix.lower()
        is_py = suffix in _PY_SUFFIXES
        is_js = suffix in _JS_SUFFIXES
        is_nb = suffix == ".ipynb"
        if not (is_py or is_js or is_nb or suffix in _TEXT_SUFFIXES):
            continue
        try:
            size = path.stat().st_size
            if size > _URL_MAX_BYTES and not (is_py or is_js or is_nb):
                continue
            text = read_text(path)
        except (OSError, TooLarge):
            continue
        rel = rel_posix(path, root)
        source = "code-ref"
        if is_nb:  # a notebook's lines depend on which references the folder check keeps: not kept
            refs = _notebook_refs(text, root) + _scan_urls(text)
        else:
            mode = "py" if is_py else "js" if is_js else ""
            kept = scancache.memo("model-refs", text, lambda t: _file_refs(t, mode), variant=mode)
            refs = [_Ref(hf_id, repo_type, line, revision) for hf_id, repo_type, line, revision, in_code in kept
                    if not (in_code and _is_local_dir(root, hf_id))]
        for ref in refs:
            if ref.repo_type == "dataset":
                comp = Component(
                    name=ref.hf_id,
                    ctype="dataset",
                    version=ref.revision,
                    ecosystem=None,
                    locations=[Location(rel, ref.line)],
                    ai=True,
                    source=source,
                    properties={"hf_id": ref.hf_id, "repo_type": "dataset"},
                )
            else:
                comp = Component(
                    name=ref.hf_id,
                    ctype="model",
                    version=ref.revision,
                    ecosystem="huggingface",
                    locations=[Location(rel, ref.line)],
                    ai=True,
                    source=source,
                    properties={"hf_id": ref.hf_id, "repo_type": "model"},
                )
            add(comp, (comp.ctype, ref.hf_id.lower(), ref.revision, "ref"))
        if path.name.lower() == "readme.md":
            card = _card_component(path, root, text)
            if card is not None:
                add(card, (card.ctype, card.name.lower(), None, "card", rel))
    return [merged[k] for k in order]


# ---------------------------------------------------------------------------------------------
# Judgement
# ---------------------------------------------------------------------------------------------


def _context(use_context: str | None) -> str:
    ctx = (use_context or "commercial").strip().lower().replace("_", "-")
    if ctx in ("nonprofit", "non-profit", "not-for-profit"):
        ctx = "non-profit"
    return ctx if ctx in USE_CONTEXTS else "commercial"  # unknown context: judge strictly


def _users(n: int) -> str:
    if n >= 1_000_000_000 and n % 1_000_000_000 == 0:
        return f"{n // 1_000_000_000}B"
    if n >= 1_000_000 and n % 1_000_000 == 0:
        return f"{n // 1_000_000}M"
    return f"{n:,}"


def _restrictiveness(v: LicenceVerdict) -> int:
    if v.commercial_ok is False:
        return 4
    if v.commercial_ok == "conditional" or v.no_derivatives or v.share_alike:
        return 3
    if v.field_of_use or v.flow_down:
        return 2
    if v.attribution_required and not v.standard_permissive:
        return 1
    return 0


def _policy_terms(values: list[str] | None) -> list[str]:
    if not values:
        return []
    return [_norm(v) for v in values if isinstance(v, str) and v.strip()]


def _policy_names(v: LicenceVerdict | None, raw: str | None) -> set[str]:
    names: set[str] = set()
    if v is not None:
        names |= {v.licence_id, _norm(v.verdict_id), _norm(v.base_verdict_id)}
        names |= _db().reverse_aliases.get(v.licence_id, set())
        names |= set(v.tags)
    if raw:
        names.add(_norm(raw))
        target = _resolve(raw)
        if target:
            names.add(target)
    return names


def _policy_match(v: LicenceVerdict | None, raw: str | None, terms: list[str]) -> str | None:
    names = _policy_names(v, raw)
    for term in terms:
        if term in names:
            return term
    return None


def _kind_word(comp: Component) -> str:
    return "dataset" if comp.ctype == "dataset" else "model"


def _evidence(v: LicenceVerdict | None, ctx: str, role: str, raw: str | None, extra: dict | None = None) -> Evidence:
    detail: dict[str, Any] = {}
    if v is not None:
        detail.update(v.to_dict())
        detail.pop("remediation", None)
    detail["use_context"] = ctx
    detail["role"] = role
    if raw:
        detail["licence_declared"] = raw
    detail["advisory"] = ADVISORY
    if extra:
        detail.update(extra)
    if v is None:
        return Evidence(source="ait-licence", record=None, url=None, detail=detail)
    return Evidence(source="ait-licence", record=v.verdict_id, url=v.text_url or None, detail=detail)


def _terms(v: LicenceVerdict, ctx: str) -> tuple[str, str, str, str]:
    """(rule_id, severity, verdict, title) for what the licence terms mean in this context."""
    commercial_like = ctx in _COMMERCIAL_LIKE
    lid = v.licence_id
    extras: list[str] = []
    if v.share_alike:
        extras.append("share-alike")
    if v.no_derivatives:
        extras.append("no-derivatives")
    tail = (" + " + " + ".join(extras)) if extras else ""
    if v.commercial_ok is False and commercial_like:
        return (
            "ait.licence.non-commercial",
            "high",
            "suspicious",
            f"licence: {lid} is non-commercial only{tail} vs use_context={ctx}",
        )
    if v.commercial_ok == "conditional" and commercial_like:
        parts: list[str] = []
        if v.attribution_required:
            parts.append("attribution required")
        if v.mau_threshold:
            parts.append(f">{_users(v.mau_threshold)} MAU clause")
        if v.condition_label:
            parts.append(v.condition_label)
        if not parts:
            parts.append("conditional commercial use")
        return ("ait.licence.conditional", "medium", "suspicious", f"licence: {' + '.join(parts)} vs use_context={ctx}")
    if v.no_derivatives:
        return (
            "ait.licence.no-derivatives",
            "medium",
            "suspicious",
            f"licence: {lid} forbids sharing adapted material (no-derivatives)",
        )
    if v.share_alike:
        return (
            "ait.licence.share-alike",
            "medium",
            "suspicious",
            f"licence: {lid} is share-alike: shared adaptations must keep the same licence",
        )
    if v.commercial_ok is False:
        return (
            "ait.licence.non-commercial",
            "info",
            "benign",
            f"licence: {lid} is non-commercial only (compatible with use_context={ctx})",
        )
    parts = []
    if v.attribution_required and not v.standard_permissive:
        parts.append("attribution required")
    if v.mau_threshold:
        parts.append(f">{_users(v.mau_threshold)} MAU clause")
    if v.condition_label:
        parts.append(v.condition_label)
    if v.field_of_use:
        parts.append("use restrictions")
    if v.flow_down and v.field_of_use:
        parts.append("must flow down to users")
    if not parts:
        return ("ait.licence.obligations", "info", "benign", f"licence: {lid} is permissive (keep licence and notices)")
    return ("ait.licence.obligations", "low", "benign", f"licence: {' + '.join(parts)} ({lid})")


def _terms_remediation(rule_id: str, v: LicenceVerdict, comp: Component, ctx: str) -> str:
    base = v.remediation.strip()
    if rule_id == "ait.licence.non-commercial" and ctx in _COMMERCIAL_LIKE:
        tail = (
            " Confirm the licence on the model/dataset card first (tags can be wrong). If this use is"
            " genuinely research or non-profit, set use_context in aibom.policy.yaml."
        )
        return (base or f"Obtain a commercial licence from the rights holder or replace this {_kind_word(comp)}.") + tail
    if rule_id == "ait.licence.conditional":
        return base or "Confirm the commercial conditions in the licence text and record how you meet them."
    if not base:
        return "Keep the licence text and required notices with anything you redistribute."
    return base


def _prefix(role: str, label: str | None, v: LicenceVerdict | None, raw: str | None) -> str:
    if role == "base_model":
        return f"base model {label}: "
    if role == "upstream":
        return f"upstream licence ({label}): "
    if role == "name-hint":
        declared = f" but declares {raw}" if raw else ""
        lid = v.licence_id if v else "?"
        return f"model id suggests {lid}{declared}: "
    return ""


def _suffix(v: LicenceVerdict, role: str) -> str:
    return " (licence inferred from model id)" if v.inferred and role in ("self", "base_model") else ""


class _Judge:
    def __init__(self, ctx: str, allow: list[str] | None, deny: list[str] | None) -> None:
        self.ctx = ctx
        self.allow = _policy_terms(allow)
        self.deny = _policy_terms(deny)
        self.findings: list[Finding] = []

    def _finding(self, comp: Component, rule_id: str, title: str, severity: str, verdict: str,
                 confidence: int, ev: Evidence, remediation: str, disc: str) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                verdict=verdict,
                confidence=max(0, min(100, int(confidence))),
                component=comp,
                evidence=[ev],
                remediation=remediation,
                maps_to=[OWASP_SUPPLY_CHAIN],
                discriminator=disc,
            )
        )

    def verdict(self, comp: Component, v: LicenceVerdict, role: str, label: str | None,
                raw: str | None, confidence: int | None = None) -> None:
        conf = v.confidence if confidence is None else min(v.confidence, confidence)
        disc = f"{role}:{label or ''}:{v.licence_id}"
        pre = _prefix(role, label, v, raw)
        suf = _suffix(v, role)
        policy_raw = raw if role == "self" else None
        denied = _policy_match(v, policy_raw, self.deny) if self.deny else None
        if denied:
            self._finding(
                comp,
                "ait.licence.denied",
                f"{pre}licence: {v.licence_id} denied by policy (matches '{denied}'){suf}",
                "high",
                "suspicious",
                conf,
                _evidence(v, self.ctx, role, raw, {"policy": "deny_model_licences", "matched": denied}),
                f"Policy deny_model_licences matches '{denied}'. Replace this {_kind_word(comp)} with one under an"
                " allowed licence, or record an approved exception (suppression with expiry). " + v.remediation,
                disc,
            )
            return  # the deny finding carries every verdict field; no second finding for the same terms
        if self.allow and not _policy_match(v, policy_raw, self.allow):
            self._finding(
                comp,
                "ait.licence.not-allowed",
                f"{pre}licence: {v.licence_id} not in allow_model_licences{suf}",
                "medium",
                "suspicious",
                conf,
                _evidence(v, self.ctx, role, raw, {"policy": "allow_model_licences"}),
                f"'{v.licence_id}' (verdict {v.verdict_id}) is not on the allow list. Review the licence text"
                f" ({v.text_url}) and add '{v.base_verdict_id}' or '{v.licence_id}' to allow_model_licences if"
                f" acceptable, or replace this {_kind_word(comp)}.",
                disc,
            )
        rule_id, severity, fverdict, title = _terms(v, self.ctx)
        self._finding(
            comp,
            rule_id,
            f"{pre}{title}{suf}",
            severity,
            fverdict,
            conf,
            _evidence(v, self.ctx, role, raw),
            _terms_remediation(rule_id, v, comp, self.ctx),
            disc,
        )

    def unknown(self, comp: Component, role: str, label: str | None, raw: str | None) -> None:
        disc = f"{role}:{label or ''}:{_norm(raw) if raw else 'none'}"
        pre = _prefix(role, label, None, None)
        if raw and _norm(raw) not in _PLACEHOLDERS:
            what = f"no verdict for declared licence '{raw}'"
        elif raw:
            what = f"declared as '{raw}' and not inferable from the id"
        else:
            what = "not declared and not inferable from the id"
        if raw and role == "self":
            denied = _policy_match(None, raw, self.deny) if self.deny else None
            if denied:
                self._finding(
                    comp, "ait.licence.denied", f"{pre}licence: {raw} denied by policy (matches '{denied}')",
                    "high", "suspicious", 90, _evidence(None, self.ctx, role, raw, {"matched": denied}),
                    f"Policy deny_model_licences matches '{denied}'. Replace this {_kind_word(comp)} or record"
                    " an approved exception.", disc,
                )
                return
            if self.allow and _norm(raw) not in _PLACEHOLDERS and not _policy_match(None, raw, self.allow):
                self._finding(
                    comp, "ait.licence.not-allowed", f"{pre}licence: {raw} not in allow_model_licences",
                    "medium", "suspicious", 80, _evidence(None, self.ctx, role, raw, {"policy": "allow_model_licences"}),
                    f"'{raw}' is not on the allow list and has no AIterprise verdict. Read the licence and add it"
                    f" to allow_model_licences if acceptable, or replace this {_kind_word(comp)}.", disc,
                )
        self._finding(
            comp,
            "ait.licence.unknown",
            f"{pre}licence unknown: {what}",
            "low",
            "unknown",
            60,
            _evidence(None, self.ctx, role, raw, {"verdict": None}),
            "Open the model or dataset card (and its LICENSE file) on Hugging Face and confirm the licence;"
            " declare it in the card's `license:` field or the file's metadata. Treat it as not cleared for"
            f" use_context={self.ctx} until reviewed.",
            disc,
        )


def _inference_name(comp: Component) -> str | None:
    if comp.ctype == "dataset":
        return None
    for key in ("hf_id", "model_id", "base_model_id", "general.name", "name"):
        val = comp.properties.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    if comp.ctype == "model-file":
        return comp.name.replace("\\", "/").rsplit("/", 1)[-1] or None
    return comp.name or None


def _base_models(comp: Component) -> list[str]:
    base = comp.properties.get("base_model")
    if isinstance(base, str):
        return [base.strip()] if base.strip() else []
    if isinstance(base, (list, tuple)):
        return [b.strip() for b in base if isinstance(b, str) and b.strip()]
    return []


def judge_licences(
    components: list[Component],
    use_context: str = "commercial",
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    result=None,
) -> list[Finding]:
    """Licence findings for models, datasets and model files (advisory, not legal advice). Given a
    `result`, records the coverage."""
    judged = [c for c in components if c.ctype in JUDGED_CTYPES]
    entry = result.examine(sources.LICENCES.name) if result is not None else None
    if entry is not None:
        entry.checked += len(judged)  # what was asked, also when the judging below fails
    findings = _judge_licences(components, use_context, allow, deny)
    if entry is not None:
        flagged = {f.component.key() for f in findings if f.component is not None}
        entry.with_data += sum(1 for c in judged if c.key() in flagged)
    return findings


def _judge_licences(components: list[Component], use_context: str, allow: list[str] | None,
                    deny: list[str] | None) -> list[Finding]:
    ctx = _context(use_context)
    judge = _Judge(ctx, allow, deny)
    for comp in components:
        if comp.ctype not in JUDGED_CTYPES:
            continue
        raw = comp.licence.strip() if isinstance(comp.licence, str) and comp.licence.strip() else None
        name = _inference_name(comp)
        seen: set[str] = set()
        primary = verdict_for(raw, name)
        hint = None
        if comp.ctype in ("model", "model-file") and name and raw and (primary is None or not primary.inferred):
            hint = _infer(name)  # what the id says, next to what the publisher declared
        if primary is not None:
            if comp.ctype == "model-file" and primary.inferred:
                primary.confidence = max(0, primary.confidence - 10)  # a file name is a weak hint
            judge.verdict(comp, primary, "self", None, raw)
            seen.add(primary.licence_id)
            upstream = list(primary.also)
            if hint is not None and hint.licence_id == primary.licence_id:
                upstream += hint.also  # e.g. an R1-Distill-Llama declared MIT still carries Llama terms
            for lid in upstream:
                if lid in seen:
                    continue
                up = _make(lid, inferred=True, basis=f"upstream licence of {name} (inference rule for the id)",
                           confidence=(hint or primary).confidence)
                judge.verdict(comp, up, "upstream", lid, None)
                seen.add(lid)
        elif raw or comp.ctype in ("model", "dataset"):
            judge.unknown(comp, "self", None, raw)
        # A declared tag that disagrees with what the id says (e.g. a Llama fine-tune tagged MIT).
        if hint is not None and hint.licence_id not in seen and (
            primary is None or _restrictiveness(hint) > _restrictiveness(primary)
        ):
            hint.basis += "; the declared licence disagrees - a fine-tune inherits its base model's terms"
            judge.verdict(comp, hint, "name-hint", None, raw, confidence=45)
            seen.add(hint.licence_id)
        for base in _base_models(comp):
            if base.lower() == comp.name.lower():
                continue
            bv = verdict_for(None, base)
            if bv is None:
                if comp.ctype == "model":
                    judge.unknown(comp, "base_model", base, None)
                continue
            if bv.licence_id in seen:
                continue
            bv.basis = f"base model {base!r}: {bv.basis}"
            judge.verdict(comp, bv, "base_model", base, None)
            seen.add(bv.licence_id)
            for lid in bv.also:
                if lid not in seen:
                    judge.verdict(comp, _make(lid, inferred=True, basis=f"upstream licence of base model {base}",
                                              confidence=bv.confidence), "upstream", lid, None)
                    seen.add(lid)
    return judge.findings


def licence_ids() -> list[str]:
    """Every licence id the matrix knows (for policy lint and docs)."""
    return sorted(_db().licences)


def iter_verdicts() -> Iterable[LicenceVerdict]:
    for key in licence_ids():
        yield _make(key, inferred=False, basis="matrix entry")
