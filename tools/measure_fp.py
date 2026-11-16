#!/usr/bin/env python3
"""Measure heuristic rules' false-positive rates on a clean corpus → data/ait/rule-quality.json.

    python tools/measure_fp.py --corpus-name "site-packages sample" \
        --packages /path/to/site-packages [--packages ...] [--project DIR ...] [--write]
    python tools/measure_fp.py --corpus-name "installed agent skills" \
        --projects-from skills.txt --family ait.skill. --merge --write

Each package directory (or `--project`, or line of a `--projects-from` file; a project may be one
file, such as an MCP config) is scanned offline as one clean project. A rule's rate is

    fp_rate_measured = clean projects where the rule fired / clean projects that gave it a chance

"A chance" means the scan examined something that rule family judges (an MCP config for
`ait.mcp.*`, a model file for `ait.model.*`, text for `ait.secret.*`, …), read from the scan's
`examined` counts. A family is written only when at least `--min-samples` projects gave it a chance;
below that the rule stays `fp_rate_measured: null` — unmeasured, never an invented number.

Only heuristic families are measured. Advisory, licence, registry and policy findings are facts
about a package, not guesses, so a "clean corpus" says nothing about them.

A corpus is chosen for the families it is clean for: `--family PREFIX` limits what a run measures,
and `--merge` then replaces only those families in the existing file. A family this run could not
measure (too few samples) keeps the entry it already had.
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


def read_project_list(path: Path) -> list[Path]:
    """One project path per line; blank lines and `#` comments are skipped."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        project = Path(line)
        if not project.exists():
            raise SystemExit(f"{path}: no such project: {project}")
        out.append(project)
    return out


def merge_quality(old: dict, new: dict, measured: list[str]) -> dict:
    """`new` plus every rule of `old` that belongs to no family in `measured`.

    A measured family replaces all of its old entries, so a rule that fired on the old corpus but
    not on the new one does not keep a stale number."""
    kept = {rule: entry for rule, entry in (old.get("rules") or {}).items()
            if not any(rule.startswith(fam) for fam in measured)}
    return {**new, "rules": dict(sorted({**kept, **new["rules"]}.items()))}


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


def to_quality(m: dict, corpus: str, min_samples: int, today: str, families: list[str] | None = None) -> dict:
    rules: dict[str, dict] = {}
    for fam, n in sorted(m["chances"].items()):
        if n < min_samples or (families is not None and fam not in families):
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
    ap.add_argument("--project", type=Path, action="append", default=[], help="one clean project (directory or file)")
    ap.add_argument("--projects-from", type=Path, action="append", default=[],
                    help="a text file naming one clean project per line")
    ap.add_argument("--corpus-name", required=True)
    ap.add_argument("--family", action="append", default=[],
                    help=f"measure only this rule family (repeatable); one of: {', '.join(FAMILIES)}")
    ap.add_argument("--min-samples", type=int, default=25)
    ap.add_argument("--merge", action="store_true",
                    help="keep the existing entries of every family this run did not measure")
    ap.add_argument("--write", action="store_true", help=f"write {OUT.name}")
    ap.add_argument("--out", type=Path, default=OUT, help="the quality file to write (and to merge into)")
    args = ap.parse_args(argv)
    families = args.family or list(FAMILIES)
    unknown = [f for f in families if f not in FAMILIES]
    if unknown:
        ap.error(f"unknown family {unknown[0]!r}; choose from: {', '.join(FAMILIES)}")
    dirs = projects(args.packages, args.project) + [p for f in args.projects_from for p in read_project_list(f)]
    if not dirs:
        ap.error("no projects to scan")

    def progress(i, n, name, rules):
        if rules or i % 25 == 0 or i == n:
            print(f"[{i}/{n}] {name}" + (f": {', '.join(rules)}" if rules else ""), file=sys.stderr)

    m = measure(dirs, progress)
    today = dt.date.today().isoformat()
    q = to_quality(m, f"{args.corpus_name} ({m['projects']} projects)", args.min_samples, today, families)
    print(json.dumps({"chances": m["chances"], "flagged_family": m["flagged_family"],
                      "flagged_rule": m["flagged_rule"]}, indent=2))
    measured = [fam for fam in families if m["chances"].get(fam, 0) >= args.min_samples]
    for fam in families:
        if fam not in measured:
            print(f"{fam}: {m['chances'].get(fam, 0)} project(s) gave it a chance, fewer than {args.min_samples}: "
                  "not measured")
    print(f"{len(q['rules'])} quality entries (families with >= {args.min_samples} chances)")
    if args.merge and args.out.exists():
        q = merge_quality(json.loads(args.out.read_text(encoding="utf-8")), q, measured)
    if args.write:
        args.out.write_text(json.dumps(q, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"written {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
