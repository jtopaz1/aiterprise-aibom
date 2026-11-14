#!/usr/bin/env python3
"""Measure heuristic rules' false-positive rates on a clean corpus → data/ait/rule-quality.json.

    python tools/measure_fp.py --corpus-name "site-packages sample" \
        --packages /path/to/site-packages [--packages ...] [--project DIR ...] [--write]

Each package directory (or `--project`) is scanned offline as one clean project. A rule's rate is

    fp_rate_measured = clean projects where the rule fired / clean projects that gave it a chance

"A chance" means the scan examined something that rule family judges (an MCP config for
`ait.mcp.*`, a model file for `ait.model.*`, text for `ait.secret.*`, …), read from the scan's
`examined` counts. A family is written only when at least `--min-samples` projects gave it a chance;
below that the rule stays `fp_rate_measured: null` — unmeasured, never an invented number.

Only heuristic families are measured. Advisory, licence, registry and policy findings are facts
about a package, not guesses, so a "clean corpus" says nothing about them.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aiterprise_scan.cache import Cache  # noqa: E402
from aiterprise_scan.scanner import ScanOptions, run_scan  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "src" / "aiterprise_scan" / "data" / "ait" / "rule-quality.json"
FAMILIES = {  # rule prefix -> examined sources that give it a chance
    "ait.mcp.desc.": ("mcp", "archives"),
    "ait.mcp.cmd.": ("mcp", "archives"),
    "ait.skill.": ("skills",),
    "ait.secret.": ("secrets",),
    "ait.model.pickle.": ("model-files", "archives"),
    "ait.archive.": ("archives",),
    "ait.pkg.typosquat": ("registry",),
}
SKIP_DIRS = {"__pycache__", "bin", "Scripts", "include"}
METHOD = ("fp_rate_measured = clean projects where the rule fired / clean projects whose scan examined something "
          "that rule family judges; written only with at least min-samples such projects (tools/measure_fp.py)")


def family_of(rule_id: str) -> str | None:
    return next((p for p in FAMILIES if rule_id.startswith(p)), None)


def projects(packages: list[Path], extra: list[Path]) -> list[Path]:
    out = list(extra)
    for root in packages:
        for p in sorted(root.iterdir()):
            if p.is_dir() and p.name not in SKIP_DIRS and not p.name.endswith((".dist-info", ".egg-info")) \
                    and not p.name.startswith((".", "_")):
                out.append(p)
    return out


def measure(dirs: list[Path], progress=None) -> dict:
    chances: Counter = Counter()
    flagged_family: Counter = Counter()
    flagged_rule: Counter = Counter()
    rule_family: dict[str, str] = {}
    examples: dict[str, list[str]] = defaultdict(list)
    for i, d in enumerate(dirs):
        result = run_scan(ScanOptions(target=d, offline=True, registry=False, all_files=True, cache=Cache()))
        for fam, sources in FAMILIES.items():
            if any(result.examined.get(s) and result.examined[s].checked for s in sources):
                chances[fam] += 1
        fams, rules = set(), set()
        for f in result.findings:
            fam = family_of(f.rule_id)
            if fam is None:
                continue
            fams.add(fam)
            rules.add(f.rule_id)
            rule_family[f.rule_id] = fam
        for fam in fams:
            flagged_family[fam] += 1
        for rule in rules:
            flagged_rule[rule] += 1
            if len(examples[rule]) < 5:
                examples[rule].append(d.name)
        if progress:
            progress(i + 1, len(dirs), d.name, sorted(rules))
    return {"projects": len(dirs), "chances": dict(chances), "flagged_family": dict(flagged_family),
            "flagged_rule": dict(flagged_rule), "rule_family": rule_family, "examples": dict(examples)}


def to_quality(m: dict, corpus: str, min_samples: int, today: str) -> dict:
    rules: dict[str, dict] = {}
    for fam, n in sorted(m["chances"].items()):
        if n < min_samples:
            continue
        base = {"corpus": corpus, "evaluated_at": today, "samples": n}
        key = fam if fam.endswith("*") else (fam + "*" if fam.endswith(".") else fam)
        rules[key] = {**base, "fp_rate_measured": round(m["flagged_family"].get(fam, 0) / n, 4),
                      "flagged": m["flagged_family"].get(fam, 0), "scope": "family"}
        for rule, k in sorted(m["flagged_rule"].items()):
            if m["rule_family"].get(rule) == fam:
                # no example paths: corpus directory names can identify the machine they came from
                rules[rule] = {**base, "fp_rate_measured": round(k / n, 4), "flagged": k, "scope": "rule"}
    return {"version": today.replace("-", "."), "method": METHOD, "rules": rules}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--packages", type=Path, action="append", default=[], help="a site-packages directory")
    ap.add_argument("--project", type=Path, action="append", default=[], help="one clean project directory")
    ap.add_argument("--corpus-name", required=True)
    ap.add_argument("--min-samples", type=int, default=25)
    ap.add_argument("--write", action="store_true", help=f"write {OUT.name}")
    args = ap.parse_args(argv)
    dirs = projects(args.packages, args.project)
    if not dirs:
        ap.error("no projects to scan")

    def progress(i, n, name, rules):
        if rules or i % 25 == 0 or i == n:
            print(f"[{i}/{n}] {name}" + (f": {', '.join(rules)}" if rules else ""), file=sys.stderr)

    m = measure(dirs, progress)
    today = dt.date.today().isoformat()
    q = to_quality(m, f"{args.corpus_name} ({m['projects']} projects)", args.min_samples, today)
    print(json.dumps({"chances": m["chances"], "flagged_family": m["flagged_family"],
                      "flagged_rule": m["flagged_rule"]}, indent=2))
    print(f"{len(q['rules'])} quality entries (families with >= {args.min_samples} chances)")
    if args.write:
        OUT.write_text(json.dumps(q, indent=2) + "\n", encoding="utf-8")
        print(f"written {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
