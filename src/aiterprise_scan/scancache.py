"""Per-file results kept between scans, so a re-scan of an unchanged tree takes seconds (design
doc 13 §5.5: a warm re-scan in under 10 s; a pre-commit hook scans the whole tree on every commit).

A scan opens a `session` on a directory and names its target with `use_tree`. Within it,
`memo(kind, text, compute)` returns `compute(text)`: from an earlier scan of the same target when a
file with the same text (by SHA-256) was analysed then, else computed and kept. `compute` must
depend on nothing but the text, the `variant` given with it, this package's code and data, and
the definitions in use.

Results are kept in one JSON file per kind and target (`<directory>/<kind>-<target hash>.json`),
with the fingerprint they were computed under: the scanner's version, every file of this package
(code and bundled data) and the installed definitions release. A file with another fingerprint
is not used. When the session ends, the file is rewritten with the results of this scan's files
only, so it holds the target as it is now. A scan that fails keeps nothing. The files of a target
not scanned for 30 days are removed, and at most `MAX_STORES` files are kept, the least recently
used going first.

The directory is trusted input: whoever can write it can hide a file's results from later scans.
Do not share it between machines or across a trust boundary (a CI cache filled by untrusted pull
requests, say). A file that cannot be read or written is ignored; outside a session, or in one
without a directory, `memo` just computes.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import hashlib
import json
import os
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from . import __version__

FORMAT = 1
MAX_STORES = 256  # files of results kept (one per kind and target); the least recently used go first
MAX_AGE_S = 30 * 24 * 3600  # results of a target not scanned for this long are removed


def package_fingerprint(pkg: Path) -> str:
    """SHA-256 over the scanner's version and every file under `pkg` (not compiled files)."""
    h = hashlib.sha256(f"aiterprise-scan {__version__} scancache {FORMAT}\n".encode())
    for p in sorted(pkg.rglob("*")):
        if p.is_file() and "__pycache__" not in p.relative_to(pkg).parts:
            data = p.read_bytes()
            h.update(f"{p.relative_to(pkg).as_posix()}\0{len(data)}\0".encode())
            h.update(data)
    return h.hexdigest()


@functools.lru_cache(maxsize=1)
def code_fingerprint() -> str:
    """This build of the scanner: its package files, and a frozen executable's own size and time
    (a frozen build's code is inside the executable, not in the package folder)."""
    fp = package_fingerprint(Path(__file__).resolve().parent)
    if getattr(sys, "frozen", False):
        st = Path(sys.executable).stat()
        fp = hashlib.sha256(f"{fp}\0{st.st_size}\0{st.st_mtime_ns}".encode()).hexdigest()
    return fp


def _text_key(text: str, variant: str) -> str:
    h = hashlib.sha256(f"{variant}\0".encode("utf-8", "surrogatepass") if variant else b"")
    h.update(text.encode("utf-8", "surrogatepass"))
    return h.hexdigest()


class _Store:
    """One kind's results for one target."""

    def __init__(self, path: Path, fingerprint: str) -> None:
        self.path = path
        self.fingerprint = fingerprint
        self.old: dict[str, Any] = {}
        self.now: dict[str, Any] = {}
        self.calls = 0
        self.reused = 0  # calls answered from an earlier scan
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and doc.get("fingerprint") == fingerprint \
                    and isinstance(doc.get("results"), dict):
                self.old = doc["results"]
        except (OSError, ValueError):
            pass

    def memo(self, text: str, compute: Callable[[str], Any], variant: str) -> Any:
        key = _text_key(text, variant)
        self.calls += 1
        if key in self.old:
            self.reused += 1
            value = self.now[key] = self.old[key]
        elif key in self.now:  # a file with the same text earlier in this scan
            value = self.now[key]
        else:
            value = self.now[key] = compute(text)
        return value

    def save(self) -> None:
        if self.now.keys() == self.old.keys():  # nothing new and nothing forgotten: only mark it used
            with contextlib.suppress(OSError):
                os.utime(self.path)
            return
        try:
            text = json.dumps({"format": FORMAT, "fingerprint": self.fingerprint, "results": self.now},
                              separators=(",", ":"))
        except (TypeError, ValueError):
            return  # a result JSON cannot hold is not kept
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass


class _Session:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.tree: str | None = None
        self.fingerprint = ""
        self.stores: dict[str, _Store] = {}

    def use_tree(self, target: Path, release_id: str | None) -> None:
        self.tree = hashlib.sha256(str(Path(target).resolve()).encode("utf-8", "surrogatepass")).hexdigest()[:24]
        self.fingerprint = hashlib.sha256(f"{code_fingerprint()}\0{release_id or 'bundled'}".encode()).hexdigest()
        self.stores = {}

    def store(self, kind: str) -> _Store:
        s = self.stores.get(kind)
        if s is None:
            s = self.stores[kind] = _Store(self.directory / f"{kind}-{self.tree}.json", self.fingerprint)
        return s

    def save(self) -> None:
        for s in self.stores.values():
            s.save()
        if self.stores:
            _prune(self.directory, {s.path for s in self.stores.values()})


def _prune(directory: Path, own: set[Path]) -> None:
    """Remove the results of targets not scanned for `MAX_AGE_S`, then all but the `MAX_STORES`
    most recently used, so that scanning many short-lived folders (CI checkouts, temporary
    directories) cannot fill the disk. Files of this session are kept."""
    try:
        files = [(p.stat().st_mtime, p) for p in directory.iterdir()
                 if p.suffix in (".json", ".tmp") and p not in own]
    except OSError:
        return
    now = time.time()
    files.sort(key=lambda e: e[0], reverse=True)
    room = MAX_STORES - len(own)
    for i, (mtime, p) in enumerate(files):
        if i >= room or now - mtime > MAX_AGE_S or p.suffix == ".tmp" and now - mtime > 3600:
            with contextlib.suppress(OSError):
                p.unlink()


_current: contextvars.ContextVar[_Session | None] = contextvars.ContextVar("scancache_session", default=None)


@contextlib.contextmanager
def session(directory: Path | None) -> Iterator[_Session | None]:
    """One scan's use of the results kept in `directory` (None: keep nothing)."""
    s = _Session(Path(directory)) if directory is not None else None
    token = _current.set(s)
    try:
        yield s
    finally:
        _current.reset(token)
    if s is not None:  # reached only when the scan did not fail
        s.save()


def use_tree(target: Path, release_id: str | None) -> None:
    """Name the scan's target and its definitions release (None: the bundled data)."""
    s = _current.get()
    if s is not None:
        s.use_tree(target, release_id)


def memo(kind: str, text: str, compute: Callable[[str], Any], variant: str = "") -> Any:
    """`compute(text)`, from an earlier scan when it saw the same text. `variant` names anything
    else the result depends on (a file name, say): results are kept per text and variant."""
    s = _current.get()
    if s is None or s.tree is None:
        return compute(text)
    return s.store(kind).memo(text, compute, variant)


def reused() -> tuple[int, int]:
    """(calls of `memo` answered from an earlier scan, calls of `memo`) in this session so far."""
    s = _current.get()
    if s is None:
        return 0, 0
    return sum(st.reused for st in s.stores.values()), sum(st.calls for st in s.stores.values())
