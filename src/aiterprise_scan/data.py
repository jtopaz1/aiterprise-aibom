"""Access to the definition data shipped inside the wheel (`aiterprise_scan/data/ait/*.json`).

These files are the build-time seed and the offline / air-gapped fallback. When SecDB serves the
`AIT/ait-bundle` release, an installed, verified bundle takes precedence (design doc 13 §5.4).
"""

from __future__ import annotations

import gzip
import json
from functools import lru_cache
from importlib import resources
from typing import Any

MAX_DECOMPRESSED = 256 * 1024 * 1024


@lru_cache(maxsize=None)
def load(name: str) -> Any:
    """Load `data/ait/<name>` (JSON, or gzip-compressed JSON for `*.gz`). Cached per process."""
    ref = resources.files("aiterprise_scan").joinpath("data", "ait", name)
    if name.endswith(".gz"):
        with ref.open("rb") as raw, gzip.GzipFile(fileobj=raw) as fh:
            blob = fh.read(MAX_DECOMPRESSED + 1)
        if len(blob) > MAX_DECOMPRESSED:
            raise ValueError(f"{name}: decompressed size exceeds {MAX_DECOMPRESSED} bytes")
        return json.loads(blob.decode("utf-8"))
    with ref.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def exists(name: str) -> bool:
    return resources.files("aiterprise_scan").joinpath("data", "ait", name).is_file()
