"""Reporters: human table, JSON, SARIF 2.1.0 (C40/C43). Reports go to stdout by default (G9)."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any, TextIO

from . import INFORMATION_URI, TOOL_NAME, __version__
from .model import SEVERITIES, SEVERITY_RANK, Finding, ScanResult, sort_findings
from .textio import printable as _safe  # every scanned string shown in the table goes through this

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
_COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"


_PLURALS = {"library": "libraries"}


def _plural(ctype: str, n: int) -> str:
    if n == 1:
        return ctype
    return _PLURALS.get(ctype, ctype + "s")


def summary(result: ScanResult) -> dict[str, Any]:
    by_type = Counter(c.ctype for c in result.components)
    by_status = Counter(f.status for f in result.findings)
    return {
        "files_walked": result.files_walked,
        "components": len(result.components),
        "ai_components": sum(1 for c in result.components if c.ai),
        "components_by_type": dict(sorted(by_type.items())),
        "findings": len(result.findings),
        "severity": result.severity_counts(active_only=True),
        "status": dict(sorted(by_status.items())),
    }


# --------------------------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------------------------

def to_json(result: ScanResult) -> dict[str, Any]:
    return {
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
        "findings": [_finding_json(f, result) for f in sort_findings(result.findings)],
        "exit_code": result.exit_code,
    }


def _finding_json(f: Finding, result: ScanResult) -> dict[str, Any]:
    from . import quality

    d = f.to_dict()
    d["examined"] = quality.examined_for(f, result)
    d["quality"] = quality.rule_quality(f.rule_id)
    return d


def dumps_json(result: ScanResult) -> str:
    return json.dumps(to_json(result), indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------------------------
# SARIF 2.1.0
# --------------------------------------------------------------------------------------------

def _rule_descriptor(f: Finding) -> dict[str, Any]:
    tags = ["security", "ai-supply-chain"] + list(f.maps_to)
    return {
        "id": f.rule_id,
        "name": "".join(part.capitalize() for part in f.rule_id.replace("-", ".").split(".")),
        "shortDescription": {"text": f.rule_id},
        "fullDescription": {"text": f.title},
        "helpUri": INFORMATION_URI,
        "defaultConfiguration": {"level": _LEVEL[f.severity]},
        "properties": {"tags": tags, "security-severity": _SECURITY_SEVERITY[f.severity]},
    }


def to_sarif(result: ScanResult, include_suppressed: bool = True) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    fallback_uri = result.target if not os.path.isabs(result.target) else "."
    for f in sort_findings(result.findings):
        if f.status in ("suppressed", "acknowledged") and not include_suppressed:
            continue
        if f.rule_id not in rules:
            rules[f.rule_id] = _rule_descriptor(f)
            rule_index[f.rule_id] = len(rule_index)
        elif SEVERITY_RANK[f.severity] > SEVERITY_RANK.get(
            _severity_of_level(rules[f.rule_id]), 0
        ):
            rules[f.rule_id]["defaultConfiguration"]["level"] = _LEVEL[f.severity]
            rules[f.rule_id]["properties"]["security-severity"] = _SECURITY_SEVERITY[f.severity]
        uri = f.location.path if f.location else fallback_uri
        region = {"startLine": f.location.line} if f.location and f.location.line else None
        physical: dict[str, Any] = {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
        if region:
            physical["region"] = region
        message = f.title
        if f.remediation:
            message += f" Remediation: {f.remediation}"
        entry: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"aiterpriseFingerprint/v1": f.fingerprint},
            "properties": {
                "severity": f.severity,
                "verdict": f.verdict,
                "confidence": f.confidence,
                "security-severity": _SECURITY_SEVERITY[f.severity],
                "evidence": [e.to_dict() for e in f.evidence],
                **({"component": f.component.display} if f.component else {}),
                **({"advisory": f.advisory_id} if f.advisory_id else {}),
                **({"kev": True} if f.kev else {}),
            },
        }
        if f.status in ("suppressed", "acknowledged", "withdrawn"):
            reason = (f.suppression or {}).get("reason", f.status)
            entry["suppressions"] = [{"kind": "external", "justification": str(reason)}]
        results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"mode": result.mode, "examined": {k: v.to_dict() for k, v in result.examined.items()}},
            }
        ],
    }


def _severity_of_level(rule: dict[str, Any]) -> str:
    score = rule.get("properties", {}).get("security-severity", "0.0")
    for sev, val in _SECURITY_SEVERITY.items():
        if val == score:
            return sev
    return "info"


def dumps_sarif(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------------------------
# Human table
# --------------------------------------------------------------------------------------------

def _use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _evidence_line(f: Finding) -> str:
    if not f.evidence:
        return ""
    e = f.evidence[0]
    bits = [e.source]
    if e.record:
        bits.append(e.record)
    extra = []
    d = e.detail
    if d.get("published"):
        extra.append(f"published {str(d['published'])[:10]}")
    av = d.get("affected_versions")
    if isinstance(av, list) and av:
        extra.append("affected " + ", ".join(av[:6]) + (" …" if len(av) > 6 else ""))
    elif isinstance(av, str):
        extra.append(av)
    for key in ("callable", "opcode", "offset", "matched", "pattern", "severity_basis"):
        if d.get(key) not in (None, "", []):
            extra.append(f"{key} {d[key]}")
    line = " ".join(bits)
    if extra:
        line += " (" + "; ".join(str(x) for x in extra) + ")"
    if len(f.evidence) > 1:
        line += f" · +{len(f.evidence) - 1} more source(s)"
    return line


def render_table(result: ScanResult, stream: TextIO, show_inventory: bool = False,
                 show_suppressed: bool = False, defs_line: str = "") -> None:
    color = _use_color(stream)
    w = stream.write
    s = summary(result)
    w(f"{TOOL_NAME} {__version__}" + (f" · {defs_line}" if defs_line else "") + "\n")
    w(f"target: {_safe(result.target)} · mode: {result.mode} · telemetry: off"
      + (f" · policy: {_safe(result.policy_path)}" if result.policy_path else "") + "\n\n")

    types = " · ".join(f"{n} {_plural(t, n)}" for t, n in s["components_by_type"].items())
    w(f"DISCOVERY  {s['files_walked']} files walked · {s['components']} components ({s['ai_components']} AI)\n")
    if types:
        w(f"           {types}\n")
    sources = []
    for name, ex in sorted(result.examined.items()):
        if ex.skipped and not ex.checked:
            sources.append(f"{name} skipped ({ex.skipped})")
        else:
            txt = f"{name} {ex.with_data}/{ex.checked}"
            if ex.errors:
                txt += f" ({ex.errors} errors)"
            if ex.skipped:
                txt += f" ({ex.skipped})"
            sources.append(txt)
    counts = s["severity"]
    active = sum(counts.values())
    sev_txt = ", ".join(f"{counts[k]} {k}" for k in SEVERITIES if counts[k])
    w(f"JUDGEMENT  {active} finding{'s' if active != 1 else ''}" + (f" ({sev_txt})" if sev_txt else "") + "\n")
    if sources:
        w("           sources (with data/checked): " + " · ".join(sources) + "\n")
    w("\n")

    for f in sort_findings(result.findings):
        hidden = f.status in ("suppressed", "acknowledged", "withdrawn", "resolved")
        if hidden and not show_suppressed:
            continue
        label = f.severity.upper()
        if color:
            label = f"{_COLOR[f.severity]}{label:<9}{_RESET}"
        else:
            label = f"{label:<9}"
        subject = _safe(f.component.display) if f.component else ""
        head = f" {label} {subject + ' — ' if subject else ''}{_safe(f.title)}"
        if hidden:
            head += f"  [{f.status}]"
        w(head + "\n")
        ev = _evidence_line(f)
        if ev:
            w(f"           evidence: {_safe(ev)}\n")
        tail = []
        if f.location:
            tail.append(f"at {_safe(f.location)}")
        if f.remediation:
            tail.append(f"fix: {_safe(f.remediation)}")
        if tail:
            w("           " + " · ".join(tail) + "\n")
        w(f"           id: {f.fingerprint} · rule: {f.rule_id} · confidence {f.confidence}\n")

    hidden_count = sum(1 for f in result.findings if f.status in ("suppressed", "acknowledged"))
    if hidden_count and not show_suppressed:
        w(f"\n           {hidden_count} suppressed/baselined finding(s) not shown (--show-suppressed)\n")

    if show_inventory and result.components:
        w("\nINVENTORY\n")
        for comp in sorted(result.components, key=lambda c: (c.ctype, c.display)):
            loc = f"  ({comp.locations[0]})" if comp.locations else ""
            spec = f" [{comp.version_spec}]" if comp.version_spec and not comp.version else ""
            ai = " AI" if comp.ai else ""
            w(f"  {comp.ctype:<12} {_safe(comp.display + spec)}{ai}{_safe(loc)}\n")

    if result.notes:
        w("\nNOTES\n")
        for note in result.notes:
            w(f"  - {_safe(note)}\n")
    if result.notices:
        w("\nDATA NOTICES (reproduced as the sources require)\n")
        for n in result.notices:
            url = f" <{n['url']}>" if n.get("url") else ""
            w(f"  - {_safe(n.get('text', ''))}{_safe(url)}\n")
    outcome = {0: "pass", 1: "policy failure", 2: "error or incomplete scan"}.get(result.exit_code, "")
    w(f"\nRESULT     exit {result.exit_code} — {outcome} · {result.duration_s:.1f}s\n")
