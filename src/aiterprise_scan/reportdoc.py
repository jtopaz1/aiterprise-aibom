"""The report document: the JSON form of a scan's result (GLOSSARY.md).

It is what `--format json` prints, what the history stores and what an upload sends. This is the
one module that knows its layout:

    build(result)        the document for a ScanResult
    TOP_LEVEL_KEYS       every key `build` writes, in order
    check_schema(doc)    refuse a document written in another layout
    project_name(doc)    the project a document belongs to
    upload_view(doc)     the document as it may leave this machine, and what stayed behind
    summary(result)      the counts every report shows (the table and the HTML page use them too)

The table, SARIF and HTML reports are rendered from a ScanResult (`report.py`, `html_report.py`);
they are not report documents.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import PureWindowsPath
from typing import Any, Iterable

from . import TOOL_NAME, __version__, providers, quality
from .model import INACTIVE_STATUSES, SEVERITIES, Finding, ScanResult, sort_findings

SCHEMA = "aiterprise-report/1"
TOP_LEVEL_KEYS = ("schema", "tool", "version", "target", "mode", "started_at", "duration_s", "policy", "summary",
                  "examined", "notes", "notices", "components", "findings", "exit_code")


class SchemaError(ValueError):
    """The document names a report schema this version does not read."""


# --------------------------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------------------------

def build(result: ScanResult) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "tool": TOOL_NAME,
        "version": __version__,
        "target": result.target,
        "mode": result.mode,
        "started_at": result.started_at,
        "duration_s": round(result.duration_s, 3),
        "policy": result.policy_path,
        "summary": summary(result),
        "examined": {k: v.to_dict() for k, v in sorted(result.examined.items())},
        "notes": list(result.notes),
        "notices": [dict(n) for n in result.notices],
        "components": [c.to_dict() for c in result.components],
        "findings": [_finding(f, result) for f in sort_findings(result.findings)],
        "exit_code": result.exit_code,
    }


def _finding(f: Finding, result: ScanResult) -> dict[str, Any]:
    d = f.to_dict()
    d["examined"] = quality.examined_for(f, result)
    d["quality"] = quality.rule_quality(f.rule_id)
    return d


def summary(result: ScanResult) -> dict[str, Any]:
    by_type = Counter(c.ctype for c in result.components)
    return {
        "files_walked": result.files_walked,
        "components": len(result.components),
        "ai_components": sum(1 for c in result.components if c.ai),
        "components_by_type": dict(sorted(by_type.items())),
        **_finding_counts((f.status, f.severity) for f in result.findings),
    }


def _finding_counts(findings: Iterable[tuple[Any, Any]]) -> dict[str, Any]:
    """`findings`, `severity` (findings that are still active) and `status` of a summary, from
    (status, severity) pairs: the one calculation behind a written summary and an upload's."""
    pairs = list(findings)
    severity = {s: 0 for s in SEVERITIES}
    for status, sev in pairs:
        if status not in INACTIVE_STATUSES and sev in severity:
            severity[sev] += 1
    by_status = Counter(status for status, _ in pairs if isinstance(status, str))
    return {"findings": len(pairs), "severity": severity, "status": dict(sorted(by_status.items()))}


# --------------------------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------------------------

def check_schema(doc: dict) -> None:
    """Raise SchemaError for a document of another layout. A document without `schema` was
    written before reports carried one, and is read as this layout."""
    schema = doc.get("schema")
    if schema is not None and schema != SCHEMA:
        raise SchemaError(f"report schema {schema!r} is not supported; this version reads {SCHEMA}")


def project_name(doc: dict) -> str:
    target = str(doc.get("target") or "").rstrip("\\/")
    return PureWindowsPath(target).name or target or "default"  # splits on both / and \


# --------------------------------------------------------------------------------------------
# The upload view
# --------------------------------------------------------------------------------------------

def upload_view(doc: dict) -> tuple[dict, dict[str, int]]:
    """The document as it may be sent to SecDB or a cloud, and how many findings of each
    third-party provider stayed on this machine. The caller's document is not changed.

    Two things never leave: third-party provider results (FD22: the `ext.*` findings, the
    providers' coverage entries and the notes about them; the summary is counted again), and local
    absolute paths (the target becomes the project name, home directories become `~`)."""
    out, kept_local = _without_provider_results(doc)
    return _without_local_paths(out), kept_local


def _without_provider_results(doc: dict) -> tuple[dict, dict[str, int]]:
    findings = doc.get("findings")
    gone = [f for f in findings if isinstance(f, dict) and providers.is_external(f.get("rule_id"))] \
        if isinstance(findings, list) else []
    kept_local: dict[str, int] = {}
    for f in gone:
        name = providers.provider_of(f["rule_id"]) or "provider"
        kept_local[name] = kept_local.get(name, 0) + 1
    names = set(providers.REGISTRY) | set(kept_local)

    def about_a_provider(note: Any) -> bool:
        return isinstance(note, str) and any(
            note.startswith(f"{n}:") or f"{providers.EXT_PREFIX}{n}." in note for n in names)

    out = dict(doc)
    if gone:
        out["findings"] = [f for f in findings if not (isinstance(f, dict) and providers.is_external(f.get("rule_id")))]
    if isinstance(doc.get("examined"), dict):
        out["examined"] = {k: v for k, v in doc["examined"].items() if k not in names}
    if isinstance(doc.get("notes"), list):
        out["notes"] = [n for n in doc["notes"] if not about_a_provider(n)]
    if gone and isinstance(doc.get("summary"), dict):
        counts = _finding_counts((f.get("status"), f.get("severity")) if isinstance(f, dict) else (None, None)
                                 for f in out["findings"])
        # only the counts a summary already carries: an older document keeps its own set of keys
        out["summary"] = {k: counts.get(k, v) for k, v in doc["summary"].items()}
    return out, kept_local


_HOME_PATH = re.compile(r"(?:[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\/\s\"']+|/(?:home|Users)/[^/\s\"']+)"
                        r"((?:[\\/][^\s\"']*)?)")


def _without_local_paths(doc: dict) -> dict:
    """Local absolute paths carry user names; nothing in an upload needs them."""
    target = str(doc.get("target") or "")
    name = project_name(doc)

    def clean(value: Any) -> Any:
        if isinstance(value, str):
            if target and target in value:
                value = value.replace(target, name)
            return _HOME_PATH.sub(lambda m: "~" + m.group(1).replace("\\", "/"), value)
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()}
        return value

    return clean(doc)
