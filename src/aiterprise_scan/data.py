"""Access to definition data: an installed, verified bundle first, then the wheel's copy.

The wheel's `aiterprise_scan/data/ait/*` files are the build-time seed and the offline /
air-gapped fallback. A bundle installed with `aiterprise-scan defs install|update` takes
precedence file by file (design doc 13 §5.4); `AITERPRISE_DEFS=bundled` ignores it.
"""

from __future__ import annotations

import gzip
import io
import json
from functools import lru_cache
from importlib import resources
from typing import Any

from . import bundles

MAX_DECOMPRESSED = 256 * 1024 * 1024


def _parse(name: str, blob: bytes) -> Any:
    if name.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(blob)) as fh:
            blob = fh.read(MAX_DECOMPRESSED + 1)
        if len(blob) > MAX_DECOMPRESSED:
            raise ValueError(f"{name}: decompressed size exceeds {MAX_DECOMPRESSED} bytes")
    return json.loads(blob.decode("utf-8"))


def _wheel(name: str):
    return resources.files("aiterprise_scan").joinpath("data", "ait", name)


@lru_cache(maxsize=None)
def load(name: str) -> Any:
    """Load `<name>` (JSON, or gzip-compressed JSON for `*.gz`). Cached per process."""
    hit = bundles.installed_file(name)
    if hit is not None:
        return _parse(name, hit[1])
    return _parse(name, _wheel(name).read_bytes())


def exists(name: str) -> bool:
    return bundles.installed_file(name) is not None or _wheel(name).is_file()


def source(name: str) -> str:
    """Where `load(name)` reads from: `bundle rel_…`, `wheel`, or `missing`."""
    hit = bundles.installed_file(name)
    if hit is not None:
        return f"bundle {hit[0]}"
    return "wheel" if _wheel(name).is_file() else "missing"
