"""Reporters: human table, JSON, SARIF 2.1.0 (C40/C43). Reports go to stdout by default (G9).

The JSON report is the report document; `reportdoc.py` owns its layout."""

from __future__ import annotations

import json
import os
from typing import Any, TextIO

from . import INFORMATION_URI, TOOL_NAME, __version__, reportdoc
from .model import SEVERITIES, SEVERITY_RANK, Finding, ScanResult, sort_findings
from .reportdoc import summary
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


# --------------------------------------------------------------------------------------------
# JSON: the report document (its layout lives in reportdoc.py)
# --------------------------------------------------------------------------------------------

def dumps_json(result: ScanResult) -> str:
    return json.dumps(reportdoc.build(result), indent=2, ensure_ascii=False) + "\n"


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


# --------------------------------------------------------------------------------------------
# Markdown: the GitHub Action's pull-request comment and job summary (C42)
# --------------------------------------------------------------------------------------------

MARKDOWN_MARKER = "<!-- aiterprise-scan report -->"
_MD_CELL = 200
_MD_NOTES = 20
_MD_STATE = {0: "passes the gate", 1: "fails the gate", 2: "incomplete scan (exit 2)"}


def _md_code(text: Any, limit: int = _MD_CELL) -> str:
    """Scanned text as one inline code span, where GitHub renders no link, image, HTML, mention or
    emoji. A backtick would close the span and a pipe would split a table cell, so both are
    replaced; line breaks and invisible characters become spaces."""
    s = " ".join(_safe(text).split()).replace("`", "'").replace("|", "¦")
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return f"`{s}`" if s else ""


def render_markdown(result: ScanResult, defs_line: str = "", max_rows: int = 50) -> str:
    """The new findings as a Markdown table, safe to post where scanned text must stay inert."""
    new = [f for f in sort_findings(result.findings) if f.status == "new"]
    hidden = sum(1 for f in result.findings if f.status in ("suppressed", "acknowledged"))
    s = summary(result)
    scope = f"{s['components']} components ({s['ai_components']} AI) · {result.mode}"
    if hidden:
        scope += f" · {hidden} suppressed or baselined"
    state = _MD_STATE.get(result.exit_code, f"exit {result.exit_code}")
    out = [MARKDOWN_MARKER, f"### {TOOL_NAME}: {state}", ""]
    if new:
        by_sev = {k: sum(1 for f in new if f.severity == k) for k in SEVERITIES}
        sev_txt = ", ".join(f"{n} {k}" for k, n in by_sev.items() if n)
        out += [f"**{len(new)} new finding{'s' if len(new) != 1 else ''}** ({sev_txt}) · {scope}", "",
                "| Severity | Finding | Where | Rule |", "|---|---|---|---|"]
        for f in new[:max_rows]:
            out.append(f"| {f.severity} | {_md_code(f.title)} | {_md_code(f.location or '')} | {_md_code(f.rule_id)} |")
        if len(new) > max_rows:
            out += ["", f"…and {len(new) - max_rows} more: the table, JSON and SARIF reports list every finding."]
    else:
        out += ["No new findings.", "", scope]
    if result.notes:
        out += ["", f"<details><summary>Notes ({len(result.notes)})</summary>", ""]
        out += [f"- {_md_code(n, 500)}" for n in result.notes[:_MD_NOTES]]
        out += ["", "</details>"]
    if result.notices:
        out += ["", "Data notices (reproduced as the sources require):", ""]
        out += [f"- {_md_code(n.get('text', ''), 1000)} {_md_code(n.get('url', ''))}".rstrip() for n in result.notices]
    tail = f"{TOOL_NAME} {__version__}" + (f" · {_safe(defs_line)}" if defs_line else "") + f" · exit {result.exit_code}"
    out += ["", f"<sub>{tail}</sub>", ""]
    return "\n".join(out)


# --------------------------------------------------------------------------------------------
# Compact: one line per new finding, for editor problem matchers and quickfix lists (C45)
# --------------------------------------------------------------------------------------------

_COMPACT_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "info", "info": "info"}


def _one_line(text: Any) -> str:
    return " ".join(_safe(text).split())


def render_compact(result: ScanResult) -> str:
    """`path:line: error|warning|info: title [severity rule]` for every new finding. A finding with
    no line points at line 1; one with no file at the project (`.`)."""
    out = []
    for f in sort_findings(result.findings):
        if f.status != "new":
            continue
        path = _one_line(f.location.path) if f.location else "."
        line = f.location.line if f.location and f.location.line else 1
        out.append(f"{path}:{line}: {_COMPACT_LEVEL[f.severity]}: {_one_line(f.title)} [{f.severity} {f.rule_id}]\n")
    return "".join(out)


# --------------------------------------------------------------------------------------------
# GitLab Code Quality: the merge-request widget (S3 GitLab CI template)
# --------------------------------------------------------------------------------------------

_CODEQUALITY_SEVERITY = {"critical": "blocker", "high": "critical", "medium": "major", "low": "minor", "info": "info"}


def dumps_codequality(result: ScanResult) -> str:
    """The new findings as a GitLab Code Quality report (a Code Climate issue list)."""
    issues = []
    for f in sort_findings(result.findings):
        if f.status != "new":
            continue
        issues.append({
            "description": f.title,
            "check_name": f.rule_id,
            "fingerprint": f.fingerprint,
            "severity": _CODEQUALITY_SEVERITY[f.severity],
            "location": {"path": f.location.path if f.location else ".",
                         "lines": {"begin": f.location.line if f.location and f.location.line else 1}},
        })
    return json.dumps(issues, indent=2, ensure_ascii=False) + "\n"
