#!/usr/bin/env python3
"""The last look at the wheel and the sdist before PyPI gets them.

    python tools/check_dist.py dist [--release]

A file uploaded to PyPI is public for good, so this fails (exit 1) when
- `dist` does not hold exactly one wheel and one sdist of the version in `__version__`;
- either holds a file that should not ship: the sdist anything but the package, its metadata and the
  licence files (no tests, no stray top-level file), the wheel anything outside the package and its
  `.dist-info`, either a compiled `.pyc` or a `__pycache__`;
- either lacks a module of `src/aiterprise_scan` or a data file that `pyproject.toml` declares as
  package data;
- with `--release`, the description PyPI will show still says the package is not released.
Other files in `dist` (the self-SBOM) are left alone.
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "aiterprise_scan"
SDIST_TOP = {"PKG-INFO", "README.md", "LICENSE", "NOTICE", "pyproject.toml", "setup.cfg", "MANIFEST.in", "src"}
UNRELEASED = re.compile(r"not released yet", re.IGNORECASE)


def version(root: Path) -> str:
    text = (root / "src" / PACKAGE / "__init__.py").read_text(encoding="utf-8")
    return re.search(r"""^__version__\s*=\s*["']([^"']+)""", text, re.MULTILINE).group(1)


def expected(root: Path) -> set[str]:
    """Paths inside the package that both archives must carry: every module, every declared data file."""
    pkg = root / "src" / PACKAGE
    out = {p.relative_to(pkg).as_posix() for p in pkg.rglob("*.py") if "__pycache__" not in p.parts}
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    for pattern in pyproject.get("tool", {}).get("setuptools", {}).get("package-data", {}).get(PACKAGE, []):
        out |= {p.relative_to(pkg).as_posix() for p in pkg.glob(pattern) if p.is_file()}
    return out


def _compiled(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return "__pycache__" in parts or path.endswith((".pyc", ".pyo"))


def _sdist(path: Path, v: str, need: set[str], release: bool) -> list[str]:
    prefix = f"{PACKAGE}-{v}/"
    with tarfile.open(path) as tar:
        files = {}
        for m in tar.getmembers():
            if m.isfile():
                files[m.name[len(prefix):] if m.name.startswith(prefix) else m.name] = m
        out = []
        for name in sorted(files):
            parts = PurePosixPath(name).parts
            if parts[0] not in SDIST_TOP or (parts[0] == "src" and (len(parts) < 3 or parts[1] not in
                                                                    (PACKAGE, f"{PACKAGE}.egg-info"))):
                out.append(f"sdist: {name} should not ship")
            elif _compiled(name):
                out.append(f"sdist: compiled file {name}")
        have = {n[len(f"src/{PACKAGE}/"):] for n in files if n.startswith(f"src/{PACKAGE}/")}
        out += [f"sdist: src/{PACKAGE}/{n} is missing" for n in sorted(need - have)]
        if release and "PKG-INFO" in files:
            text = tar.extractfile(files["PKG-INFO"]).read().decode("utf-8", "replace")
            if UNRELEASED.search(text):
                out.append("sdist: the description still says 'Not released yet'")
    return out


def _wheel(path: Path, v: str, need: set[str], release: bool) -> list[str]:
    info = f"{PACKAGE}-{v}.dist-info/"
    with zipfile.ZipFile(path) as whl:
        names = [n for n in whl.namelist() if not n.endswith("/")]
        out = []
        for name in sorted(names):
            if not (name.startswith(PACKAGE + "/") or name.startswith(info)):
                out.append(f"wheel: {name} should not ship")
            elif _compiled(name):
                out.append(f"wheel: compiled file {name}")
        have = {n[len(PACKAGE) + 1:] for n in names if n.startswith(PACKAGE + "/")}
        out += [f"wheel: {PACKAGE}/{n} is missing" for n in sorted(need - have)]
        if release and info + "METADATA" in names:
            if UNRELEASED.search(whl.read(info + "METADATA").decode("utf-8", "replace")):
                out.append("wheel: the description still says 'Not released yet'")
    return out


def problems(dist: Path, root: Path = ROOT, release: bool = False) -> list[str]:
    v = version(root)
    need = expected(root)
    wanted = {"wheel": (f"{PACKAGE}-{v}-py3-none-any.whl", "*.whl", _wheel),
              "sdist": (f"{PACKAGE}-{v}.tar.gz", "*.tar.gz", _sdist)}
    out = []
    for kind, (name, pattern, check) in wanted.items():
        found = sorted(p.name for p in Path(dist).glob(pattern))
        if found != [name]:
            out.append(f"{kind}: expected exactly {name}, found {', '.join(found) or 'none'}")
        if name in found:
            out += check(Path(dist) / name, v, need, release)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dist", type=Path)
    ap.add_argument("--root", type=Path, default=ROOT, help="the source tree the archives were built from")
    ap.add_argument("--release", action="store_true", help="also refuse a description that says 'Not released yet'")
    args = ap.parse_args(argv)
    found = problems(args.dist, root=args.root, release=args.release)
    for p in found:
        print(p)
    if not found:
        print(f"ok: the wheel and sdist of {version(args.root)} carry the package and nothing else")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
