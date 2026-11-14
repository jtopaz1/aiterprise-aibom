"""On-disk cache for live-API answers (`~/.aiterprise/cache`, override with AITERPRISE_CACHE_DIR).

Live results are cached per artefact so CI re-runs are cheap and polite (design doc 13 §4.7);
`--offline` reads only from here and from the bundled definitions.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

DEFAULT_TTL = 24 * 3600


def default_dir() -> Path:
    env = os.environ.get("AITERPRISE_CACHE_DIR")
    if env:
        return Path(env)
    return Path.home() / ".aiterprise" / "cache"


class Cache:
    def __init__(self, root: Path | None = None, ttl: int = DEFAULT_TTL, enabled: bool = True) -> None:
        self.root = root or default_dir()
        self.ttl = ttl
        self.enabled = enabled

    def _path(self, namespace: str, key: str) -> Path:
        safe = key if key.replace("-", "").replace("_", "").replace(".", "").isalnum() and len(key) < 100 \
            else hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.root / namespace / f"{safe}.json"

    def get(self, namespace: str, key: str, allow_stale: bool = False) -> Any | None:
        if not self.enabled:
            return None
        path = self._path(namespace, key)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not allow_stale and time.time() - entry.get("stored_at", 0) > self.ttl:
            return None
        return entry.get("value")

    def put(self, namespace: str, key: str, value: Any) -> None:
        if not self.enabled:
            return
        path = self._path(namespace, key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps({"stored_at": time.time(), "value": value}), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass  # a cache that cannot be written is not an error
