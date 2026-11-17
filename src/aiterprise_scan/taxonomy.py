"""Component taxonomy lookups (design doc 13 §4.2)."""

from __future__ import annotations

from functools import lru_cache

from . import data
from .model import normalize_name


@lru_cache(maxsize=1)
def _libraries() -> dict[str, dict[str, str]]:
    raw = data.load("taxonomy.json")["libraries"]
    return {eco: {normalize_name(k, eco): v for k, v in names.items()} for eco, names in raw.items()}


def ai_category(name: str, ecosystem: str | None) -> str | None:
    """The taxonomy category of an AI package, or None if it is not an AI component."""
    if not ecosystem:
        return None
    return _libraries().get(ecosystem, {}).get(normalize_name(name, ecosystem))


def ai_names(ecosystem: str) -> frozenset[str]:
    """Every AI package name of an ecosystem, normalised."""
    return frozenset(_libraries().get(ecosystem, {}))


def is_ai_package(name: str, ecosystem: str | None) -> bool:
    return ai_category(name, ecosystem) is not None


@lru_cache(maxsize=1)
def python_import_map() -> dict[str, str]:
    """Top-level (or dotted) Python import name -> PyPI distribution name."""
    return dict(data.load("taxonomy.json")["python_imports"])
