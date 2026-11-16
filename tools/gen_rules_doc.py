#!/usr/bin/env python3
"""Generate docs/rules.md from the rule data and the scanner's quality table.

    python tools/gen_rules_doc.py          # rewrite docs/rules.md
    python tools/gen_rules_doc.py --check  # exit 1 if it is stale (tests/test_docs.py does the same)

Data-file rules (command rules, poison patterns, model rules) are listed straight from
`src/aiterprise_scan/data/ait/`; rules raised by code are listed from CODE_RULES below. The
false-positive column is what the scanner itself reports (`quality.rule_quality`): a measured rate,
or "not measured".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "aiterprise_scan" / "data" / "ait"
OUT = ROOT / "docs" / "rules.md"

# (rule id, default severity, what it means). Severity "varies" = derived from the evidence.
CODE_RULES: dict[str, list[tuple[str, str, str]]] = {
    "Packages": [
        ("ait.pkg.malicious", "critical", "The exact version is a known-malicious release (OSV `MAL-`, SecDB). Only an expiring suppression naming the fingerprint accepts it."),
        ("ait.pkg.malicious-range", "medium", "The declared range admits a known-malicious version; pin outside it."),
        ("ait.pkg.malicious-unpinned", "low", "No exact version, and some version of this package is known-malicious."),
        ("ait.pkg.nonexistent", "high", "The name does not exist on PyPI/npm — a hallucinated or slopsquat-able dependency."),
        ("ait.pkg.security-holder", "critical", "npm replaced the package with a security holder: it was malicious."),
        ("ait.pkg.new-package", "medium", "First published in the last 72 hours."),
        ("ait.pkg.version-missing", "medium", "The pinned version does not exist on the registry (yanked or never published)."),
        ("ait.pkg.typosquat", "medium", "The name looks like a widely used or AI package (a lookalike)."),
        ("ait.pkg.secdb.<verdict>", "varies", "SecDB's verdict for the package (logged in only)."),
    ],
    "Vulnerabilities": [
        ("ait.vuln.advisory", "varies", "An OSV advisory affects this exact version; severity from the CVSS v3 base score."),
        ("ait.vuln.kev", "critical", "As above, and a CVE alias is in CISA's Known Exploited Vulnerabilities catalog."),
    ],
    "Model files (SecDB)": [
        ("ait.model.hash.<verdict>", "varies", "The file's SHA-256 is known to SecDB (logged in only)."),
    ],
    "MCP servers": [
        ("ait.mcp.scope.broad-filesystem", "medium", "A filesystem server is given the home directory or a drive root."),
        ("ait.mcp.net.plain-http", "medium", "A remote MCP server is reached over plain HTTP."),
        ("ait.mcp.secdb.<verdict>", "varies", "SecDB lists the server's URL (matched by an 8-hex SHA-256 prefix)."),
        ("ait.mcp.reputation.<tier>", "varies", "SecDB's provenance assessment of a named MCP server; `clean` is never reported as safe."),
    ],
    "Package archives": [
        ("ait.archive.pth-exec-payload", "critical", "A `.pth` file decodes and executes code at every Python start-up."),
        ("ait.archive.pth-network-or-process", "high", "A `.pth` file starts processes or opens network connections at start-up."),
        ("ait.archive.pth-startup-code", "low", "A `.pth` file runs code at start-up."),
        ("ait.archive.setup-exec-payload", "critical", "`setup.py` executes decoded code when built or installed."),
        ("ait.archive.path-traversal", "high", "A member escapes the extraction directory, is a link out of it, or is a device file."),
    ],
    "Licences": [
        ("ait.licence.non-commercial", "high/info", "Non-commercial terms: high under a commercial `use_context`, info otherwise."),
        ("ait.licence.conditional", "medium", "Use is allowed only under conditions (user caps, acceptable-use policies)."),
        ("ait.licence.no-derivatives", "medium", "No derivatives: fine-tuning or redistribution is not allowed."),
        ("ait.licence.share-alike", "medium", "Derivatives must carry the same licence."),
        ("ait.licence.obligations", "info/low", "Permissive: keep the licence and notices."),
        ("ait.licence.denied", "high", "Matches `deny_model_licences` in the policy."),
        ("ait.licence.not-allowed", "medium", "Not in `allow_model_licences` in the policy."),
        ("ait.licence.unknown", "low", "No licence could be determined for a model or dataset."),
    ],
    "Policy": [
        ("ait.policy.denied-package", "high", "Matches `deny_packages` in the policy."),
    ],
    # Not AIterprise rules: a provider's own result, shown under `ext.<provider>.*` and never
    # measured or tuned here, so the FP column always reads "not measured".
    "Third-party providers (your own key)": [
        ("ext.virustotal.malicious", "high", "VirusTotal's result, not an AIterprise rule (`--byo virustotal=ENV_VAR`): 5 or more engines flag the file's SHA-256 as malicious. See [Third-party providers](providers.md)."),
        ("ext.virustotal.suspicious", "medium", "VirusTotal's result: 1 to 4 engines flag the file as malicious, or engines flag it as suspicious only — a few engines can be a false positive."),
    ],
}

INTRO = """\
# Rules reference

<!-- generated by tools/gen_rules_doc.py — do not edit by hand -->

Every finding names a rule id. The **FP rate** column is the false-positive rate the scanner itself
reports for the rule: measured on a corpus by `tools/measure_fp.py`, or **not measured** — never an
estimate. A measured rate is the share of clean projects (that gave the rule something to judge) on
which it fired anyway.

Severities are defaults; `aibom.policy.yaml` decides which ones fail the build (`fail_on`).
"""


def _quality():
    os.environ["AITERPRISE_DEFS"] = "bundled"  # document what ships, not this machine's installed bundle
    sys.path.insert(0, str(ROOT / "src"))
    from aiterprise_scan import quality

    return quality.rule_quality


def _rate(q: dict) -> str:
    r = q.get("fp_rate_measured")
    if r is None:
        return "not measured"
    return f"{r * 100:.2f} % (n={q.get('samples')})"


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def _load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def render() -> str:
    rq = _quality()
    out = [INTRO]

    for family, rules in CODE_RULES.items():
        out += [f"## {family}", "", "| Rule | Severity | FP rate | Meaning |", "|---|---|---|---|"]
        for rid, sev, what in rules:
            out.append(f"| `{rid}` | {sev} | {_rate(rq(rid))} | {_cell(what)} |")
        out.append("")

    out += ["## Model files", "", "Static analysis only — nothing is unpickled or loaded.", "",
            "| Rule | Severity | FP rate | Meaning |", "|---|---|---|---|"]
    for rid, r in _load("model-rules.json")["rules"].items():
        out.append(f"| `{rid}` | {r.get('severity')} | {_rate(rq(rid))} | {_cell(r.get('description', ''))} |")
    out.append("")

    sys.path.insert(0, str(ROOT / "src"))
    from aiterprise_scan import secrets

    kinds = list(dict.fromkeys(kind for _rid, kind, _rx in secrets._RULES))
    out += ["## Secrets", "",
            "AI-provider and cloud keys in configuration and code, always reported redacted (severity high). "
            "The rule id is `ait.secret.<kind>`.", "",
            "| Rule | FP rate |", "|---|---|"]
    out.append(f"| `ait.secret.*` (family) | {_rate(rq('ait.secret.*'))} |")
    for kind in kinds:
        rid = f"ait.secret.{kind}"
        out.append(f"| `{rid}` | {_rate(rq(rid))} |")
    out.append("")

    cmd = _load("command-rules.json")["rules"]
    out += ["## Dangerous commands", "",
            "Matched in MCP server commands, skill scripts and package install scripts. The rule id is "
            "`ait.mcp.cmd.<id>`, `ait.skill.cmd.<id>` or `ait.archive.cmd.<id>`.", "",
            "| Id | Category | Severity | FP rate | Meaning |", "|---|---|---|---|---|"]
    for r in cmd:
        rate = _rate(rq(f"ait.mcp.cmd.{r['id']}"))
        out.append(f"| `{r['id']}` | {r['category']} | {r['severity']} | {rate} | {_cell(r['description'])} |")
    out.append("")

    poison = _load("poison-patterns.json")["rules"]
    out += ["## Poisoned descriptions and instructions", "",
            "Matched in MCP tool descriptions and agent-skill text. The rule id is `ait.mcp.desc.<id>` or "
            "`ait.skill.desc.<id>`.", "",
            "| Id | Category | Severity | FP rate | Meaning |", "|---|---|---|---|---|"]
    for r in poison:
        rate = _rate(rq(f"ait.mcp.desc.{r['id']}"))
        out.append(f"| `{r['id']}` | {r['category']} | {r['severity']} | {rate} | {_cell(r['description'])} |")
    out.append("")

    out += ["## Coverage", "",
            "`ait.<family>.not-analysable` (medium) marks a file the scanner had to skip — a manifest it could "
            "not parse, an agent config, a skill script or part of a model file. It is never passed as clean.", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if docs/rules.md is stale")
    args = ap.parse_args(argv)
    text = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("docs/rules.md is stale: run python tools/gen_rules_doc.py")
            return 1
        print("docs/rules.md is up to date")
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
