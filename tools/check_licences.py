#!/usr/bin/env python3
"""Release licence check: zero runtime dependencies, and every bundled data file is accounted for.

    python tools/check_licences.py

Fails (exit 1) when
- `pyproject.toml` declares a runtime dependency (the engine is standard-library only by design);
- a file under `src/aiterprise_scan/data/ait/` is not named in NOTICE (its source and licence);
- NOTICE names a data file that no longer exists.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def problems(root: Path = ROOT) -> list[str]:
    out: list[str] = []
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8")).get("project", {})
    if project.get("dependencies"):
        out.append(f"pyproject.toml declares runtime dependencies: {project['dependencies']}")
    notice = (root / "NOTICE").read_text(encoding="utf-8")
    named = set(re.findall(r"data/ait/([\w.\-]+)", notice))
    data_dir = root / "src" / "aiterprise_scan" / "data" / "ait"
    present = {p.name for p in data_dir.iterdir() if p.is_file()}
    for name in sorted(present - named):
        out.append(f"data/ait/{name} is shipped but NOTICE does not say where it comes from")
    for name in sorted(named - present):
        out.append(f"NOTICE names data/ait/{name}, which is not shipped")
    return out


def main() -> int:
    found = problems()
    for p in found:
        print(f"licence check: {p}")
    if not found:
        print("licence check: OK (no runtime dependencies; every data file is attributed in NOTICE)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
