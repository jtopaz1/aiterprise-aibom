"""Rule quality and per-finding coverage metadata (design doc 13 §4.3, differentiator #2).

Every finding is shown with the rule's measured false-positive rate — or, until a rule has been
measured on a labelled corpus, with `fp_rate_measured: null`, never an invented number. Measured
values live in `data/ait/rule-quality.json` (written by `tools/measure_fp.py`); model rules carry
their own `quality` block in `model-rules.json`.

`examined` answers "how many sources could have said something about this, and how many did":
`sources` counts the sources consulted for the finding's family in this scan (skipped ones are
listed apart), `with_data` the distinct sources cited in its evidence.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from . import data, sources
from .model import Finding, ScanResult
from .providers import is_external

UNMEASURED = {"fp_rate_measured": None, "corpus": None, "evaluated_at": None}

@lru_cache(maxsize=1)
def _measured() -> dict[str, dict[str, Any]]:
    if not data.exists("rule-quality.json"):
        return {}
    return dict(data.load("rule-quality.json").get("rules") or {})


@lru_cache(maxsize=1)
def _model_rules() -> dict[str, dict[str, Any]]:
    rules = data.load("model-rules.json").get("rules") or {}
    return {rid: r.get("quality") or {} for rid, r in rules.items() if isinstance(r, dict)}


def rule_quality(rule_id: str) -> dict[str, Any]:
    if is_external(rule_id):
        # a third party's result (`ext.<provider>.*`): never measured or tuned here, whatever the
        # quality data says (design doc 13 FD22)
        return dict(UNMEASURED)
    measured = _measured()
    hit = measured.get(rule_id)
    if hit is None:
        prefixes = [k for k in measured if k.endswith("*") and rule_id.startswith(k[:-1])]
        hit = measured[max(prefixes, key=len)] if prefixes else None
    if hit is None:
        hit = _model_rules().get(rule_id)
    return {**UNMEASURED, **(hit or {})}


def examined_for(f: Finding, result: ScanResult) -> dict[str, Any]:
    if is_external(f.rule_id):
        # the provider is the one source, and it answered for this file (even when a later call
        # in the same scan was refused)
        return {"sources": 1, "with_data": len({e.source for e in f.evidence})}
    family = sources.for_rule(f.rule_id)
    consulted = [s for s in family if s in result.examined and not result.examined[s].skipped]
    skipped = [s for s in family if s in result.examined and result.examined[s].skipped]
    out: dict[str, Any] = {"sources": len(consulted), "with_data": len({e.source for e in f.evidence})}
    if skipped:
        out["skipped"] = skipped
    return out
