"""Repository walker: git-aware (root `.gitignore`), skips vendored/virtual-env trees.

Scanned content is untrusted (design doc 13 §5.6): symlinks are not followed and the walk is
capped so a hostile tree cannot exhaust the scanner.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .textio import TooLarge, read_text

ALWAYS_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".aiterprise",
}

DEFAULT_MAX_FILES = 200_000
MAX_GITIGNORE_BYTES = 1024 * 1024  # a larger .gitignore is not read (its rules are not applied)


@dataclass
class IgnoreRule:
    pattern: str
    negate: bool = False
    dir_only: bool = False
    anchored: bool = False


@dataclass
class GitIgnore:
    rules: list[IgnoreRule] = field(default_factory=list)

    @classmethod
    def load(cls, root: Path) -> "GitIgnore":
        path = root / ".gitignore"
        rules: list[IgnoreRule] = []
        if path.is_file():
            try:
                text = read_text(path, MAX_GITIGNORE_BYTES)
            except (OSError, TooLarge):
                text = ""  # walking more files is the safe direction for a scanner
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                negate = line.startswith("!")
                if negate:
                    line = line[1:]
                dir_only = line.endswith("/")
                line = line.rstrip("/")
                anchored = line.startswith("/") or "/" in line
                line = line.lstrip("/")
                if line:
                    rules.append(IgnoreRule(line, negate, dir_only, anchored))
        return cls(rules)

    def ignored(self, rel: str, is_dir: bool) -> bool:
        result = False
        name = rel.rsplit("/", 1)[-1]
        for rule in self.rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.anchored:
                hit = fnmatch.fnmatchcase(rel, rule.pattern) or fnmatch.fnmatchcase(
                    rel, rule.pattern + "/**"
                )
            else:
                hit = fnmatch.fnmatchcase(name, rule.pattern)
            if hit:
                result = not rule.negate
        return result


def rel_posix(path: Path, root: Path) -> str:
    """`path` relative to `root` in posix form; `path` itself when it is not under `root`.

    Every analyzer names each file this way, so the common case (a path that starts with the root's
    own spelling, which `walk` keeps) is a string slice; anything else goes to `relative_to`."""
    p, r = str(path), str(root)
    if r == ".":
        return path.as_posix()  # what relative_to(".") gives, and its fallback, for every path
    if p.startswith(r):
        rest = p[len(r):]
        if not rest:
            return "."
        if r.endswith(os.sep):  # a filesystem root: "/" or "C:\\"
            pass
        elif rest[0] == os.sep:
            rest = rest[1:]
        else:
            rest = ""  # a sibling that only starts with the root's name: let relative_to decide
        if rest:
            return rest.replace("\\", "/") if os.sep == "\\" else rest
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


_TEST_DIRS = {"test", "tests", "testing", "__tests__", "spec", "specs", "e2e", "testdata", "fixtures",
              "__fixtures__", "__mocks__"}
_TEST_FILE_RE = re.compile(r"(?:^test_.*\.py$|^conftest\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[cm]?[jt]sx?$"
                           r"|Tests?\.(?:java|kt|cs)$)")


def is_test_path(rel: str) -> bool:
    """Whether a root-relative posix path is test code or test data, not the application itself."""
    *dirs, name = rel.split("/")
    return any(d.lower() in _TEST_DIRS for d in dirs) or bool(_TEST_FILE_RE.search(name))


def walk(root: Path, all_files: bool = False, max_files: int = DEFAULT_MAX_FILES) -> list[Path]:
    """Return regular files under `root`, sorted, without following symlinks.

    Paths keep the caller's spelling of `root` (no `resolve()`), so `p.relative_to(root)` always
    works — on Windows a resolved path can differ from the given one (8.3 short names such as
    `RUNNER~1`, drive-letter case), which made every path fall outside the root.
    """
    root = Path(root)
    if root.is_file():
        return [root]
    ignore = GitIgnore() if all_files else GitIgnore.load(root)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            if d in ALWAYS_SKIP_DIRS:
                continue
            full = current / d
            if full.is_symlink():
                continue
            if ignore.ignored(rel_posix(full, root), True):
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = current / name
            if full.is_symlink():
                continue
            if ignore.ignored(rel_posix(full, root), False):
                continue
            found.append(full)
            if len(found) >= max_files:
                return found
    return found
