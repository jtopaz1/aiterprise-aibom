#!/usr/bin/env python3
"""Print the CHANGELOG.md section of one release: the notes of its GitHub release.

    python tools/release_notes.py vX.Y.Z      (or X.Y.Z)

Exits 1 when CHANGELOG.md has no section for that version, or an empty one, so a release cannot go
out without notes.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
_HEADING = re.compile(r"^## (\S+) — \d{4}-\d{2}-\d{2}\s*$", re.MULTILINE)


def section(text: str, version: str) -> str:
    """The body of `## VERSION — DATE`, up to the next release heading, with surrounding blank lines cut."""
    headings = list(_HEADING.finditer(text))
    for i, heading in enumerate(headings):
        if heading.group(1) == version:
            end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
            body = text[heading.end():end].strip("\n")
            if not body.strip():
                raise LookupError(f"the CHANGELOG section of {version} is empty")
            return body + "\n"
    raise LookupError(f"CHANGELOG.md has no section for {version}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    version = args[0].removeprefix("v")
    try:
        sys.stdout.write(section(CHANGELOG.read_text(encoding="utf-8"), version))
    except LookupError as exc:
        print(f"release_notes: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
