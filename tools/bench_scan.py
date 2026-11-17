#!/usr/bin/env python3
"""Scan speed against design doc 13 §5.5: a cold scan of a 10,000-file monorepo in under 60 s (under
120 s with live network checks), and a re-scan of it unchanged in under 10 s.

    python tools/bench_scan.py [--files 10000] [--online] [--check SECONDS] [--check-warm SECONDS]
                               [--work DIR] [--exe BINARY] [--json FILE]

It builds a monorepo of exactly `--files` files: packages of 100 files, each with a requirements.txt,
a package.json, a README, three config files, eight TypeScript modules and the rest Python modules
copied from this interpreter's standard library (real code, real sizes; the tree differs between
Python versions, so the report names the version). One package also holds the killer demo's five
planted problems, so the timed scan has to judge files, not just walk them.

The tree is then scanned twice (offline unless `--online`), each time by the CLI in a new process (start-up, data
loading and the report included), with a cache directory that starts empty: the first scan is the
cold one; the second is a re-scan of the unchanged tree, with the operating system's file cache
warm and the per-file results the first scan kept (`scancache`). `--check` fails (exit 1) when the
first scan takes longer than SECONDS, a planted problem is missed, or a scan does not exit 1;
`--check-warm` when the second takes longer than its SECONDS.

`--online` scans without `--offline`, so each scan also asks OSV and the package registries, and the
check also fails unless every report shows that both answered (`killer_demo.mode_problems`). Neither
mode uses SecDB: the scans get no API key and a home directory of their own, so no stored login.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import subprocess
import sys
import sysconfig
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import killer_demo  # noqa: E402

PLANTED = Path("packages") / "pkg000" / "service"
PACKAGE_FILES = 100
TS_PER_PACKAGE = 8
_SKIP_PARTS = {"test", "tests", "idlelib", "lib2to3", "turtledemo", "site-packages", "__pycache__"}

REQUIREMENTS = "openai==1.50.0\nrequests==2.32.3\nnumpy==2.1.0\npydantic==2.9.2\n"
CONFIG_YAML = "service:\n  name: {name}\n  replicas: 2\n  model: gpt-4o-mini\n  timeout_s: 30\n"
ENV_EXAMPLE = "OPENAI_API_KEY=your-key-here\nOPENAI_BASE_URL=https://api.openai.com/v1\nLOG_LEVEL=info\n"


def _python_pool() -> list[Path]:
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    pool = sorted((p for p in stdlib.rglob("*.py")
                   if p.is_file() and not _SKIP_PARTS & set(p.relative_to(stdlib).parts)),
                  key=lambda p: p.relative_to(stdlib).as_posix())
    if len(pool) < 50:
        raise RuntimeError(f"only {len(pool)} standard-library sources under {stdlib}: not a usable pool")
    return pool


def _ts_module(pkg: int, i: int) -> str:
    return (f'import {{ readFile }} from "node:fs/promises";\nimport path from "node:path";\n\n'
            f"export interface Record{i} {{\n  id: string;\n  name: string;\n  tags: string[];\n"
            f"  score: number;\n}}\n\n"
            f"export async function load{i}(dir: string): Promise<Record{i}[]> {{\n"
            f'  const raw = await readFile(path.join(dir, "pkg{pkg:03d}-{i}.json"), "utf8");\n'
            f"  const rows = JSON.parse(raw) as Record{i}[];\n"
            f"  return rows.filter((r) => r.score > {i}).sort((a, b) => b.score - a.score);\n}}\n\n"
            f"export function summarise{i}(rows: Record{i}[]): string {{\n"
            f"  const tags = new Set(rows.flatMap((r) => r.tags));\n"
            f"  return `${{rows.length}} records, ${{tags.size}} tags`;\n}}\n") * 3


def build_tree(root: Path, files: int, seed: int = 7) -> dict:
    """Write the monorepo under `root` (which must not exist yet); return its size."""
    if files < 20:
        raise ValueError("at least 20 files: the planted package alone has 4")
    pool = _python_pool()
    docs = sorted((ROOT / "docs").glob("*.md"))
    rng = random.Random(seed)
    root.mkdir(parents=True)
    killer_demo.build_repo(root / PLANTED)
    count = sum(1 for p in (root / PLANTED).iterdir() if p.is_file())

    def put(path: Path, data: bytes | str) -> bool:
        nonlocal count
        if count >= files:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8", newline="\n")
        else:
            path.write_bytes(data)
        count += 1
        return True

    pkg = 0
    while count < files:
        d = root / "packages" / f"pkg{pkg:03d}"
        name = f"pkg{pkg:03d}"
        fixed = [
            ("requirements.txt", REQUIREMENTS),
            ("package.json", json.dumps({"name": f"@mono/{name}", "version": "1.0.0", "private": True,
                                         "dependencies": {"openai": "^4.56.0", "zod": "^3.23.8"}}, indent=2)),
            ("README.md", docs[pkg % len(docs)].read_text(encoding="utf-8") if docs else f"# {name}\n"),
            ("config.yaml", CONFIG_YAML.format(name=name)),
            ("settings.json", json.dumps({"name": name, "retries": 3, "endpoints": ["/health", "/v1/run"]})),
            (".env.example", ENV_EXAMPLE),
        ]
        for rel, data in fixed:
            put(d / rel, data)
        for i in range(TS_PER_PACKAGE):
            put(d / "web" / f"mod{i}.ts", _ts_module(pkg, i))
        for j in range(PACKAGE_FILES - len(fixed) - TS_PER_PACKAGE):
            if not put(d / "src" / f"m{j // 20}" / f"f{j}.py", pool[rng.randrange(len(pool))].read_bytes()):
                break
        pkg += 1
    written = [p for p in root.rglob("*") if p.is_file()]
    return {"files": len(written), "bytes": sum(p.stat().st_size for p in written)}


def _scan(root: Path, out: Path, cache: Path, exe: list[str] | None,
          online: bool = False) -> tuple[float, int, dict]:
    cmd = (exe or [sys.executable, "-m", "aiterprise_scan"]) + [
        "scan", str(root), "--format", "json", "--out", str(out)] + ([] if online else ["--offline"])
    env = {**os.environ, "AITERPRISE_CACHE_DIR": str(cache), "AITERPRISE_DEFS": "bundled",
           "AITERPRISE_HOME": str(cache.parent / "home")}
    env.pop("AITERPRISE_API_KEY", None)
    if not exe:
        env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src")] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    t = time.perf_counter()
    code = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800).returncode
    seconds = time.perf_counter() - t
    report = json.loads((out / "report.json").read_text(encoding="utf-8")) if (out / "report.json").is_file() else {}
    return seconds, code, report


def run(work: Path, files: int, exe: list[str] | None = None, online: bool = False) -> dict:
    tree = work / "mono"
    info = build_tree(tree, files)
    res = {**info, "python": platform.python_version(), "platform": platform.platform(terse=True),
           "online": online, "seconds": [], "exit": [], "missed": [], "mode": []}
    for i in range(2):
        seconds, code, report = _scan(tree, work / f"out{i}", work / "cache", exe, online=online)
        res["seconds"].append(round(seconds, 2))
        res["exit"].append(code)
        findings = report.get("findings", [])
        for label, test in killer_demo.EXPECT.items():
            if not any(test(f) for f in findings) and label not in res["missed"]:
                res["missed"].append(label)
        for problem in killer_demo.mode_problems(report, online):
            if problem not in res["mode"]:
                res["mode"].append(problem)
    res["peak_rss_mb"] = _children_peak_rss_mb()
    return res


def _children_peak_rss_mb() -> float | None:
    """Peak resident memory of the largest scan process (Linux and macOS; None elsewhere)."""
    try:
        import resource
    except ImportError:
        return None
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return round(peak / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)  # bytes on macOS, KiB on Linux


def problems(res: dict, budget: float, warm_budget: float | None = None) -> list[str]:
    out = []
    if res["seconds"][0] > budget:
        out.append(f"the first scan took {res['seconds'][0]:.1f} s, over the {budget:g} s budget")
    if warm_budget is not None and res["seconds"][1] > warm_budget:
        out.append(f"the second scan took {res['seconds'][1]:.1f} s, over the {warm_budget:g} s budget for a "
                   "re-scan of an unchanged tree")
    out += [f"missed: {label}" for label in res["missed"]]
    out += [f"scan {i + 1} exited {code}, not 1" for i, code in enumerate(res["exit"]) if code != 1]
    out += res.get("mode", [])
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--files", type=int, default=10_000)
    ap.add_argument("--online", action="store_true",
                    help="scan without --offline (OSV and the registries are asked; no SecDB) and fail unless they answered")
    ap.add_argument("--check", type=float, metavar="SECONDS", help="fail if the first scan takes longer")
    ap.add_argument("--check-warm", type=float, metavar="SECONDS",
                    help="with --check: also fail if the second scan (unchanged tree) takes longer")
    ap.add_argument("--work", type=Path, help="working directory, which must not hold a tree yet")
    ap.add_argument("--exe", help="scan with this executable (e.g. a release binary) instead of this checkout")
    ap.add_argument("--json", type=Path, help="also write the result to this file")
    args = ap.parse_args(argv)
    tmp = None
    work = args.work
    if work is None:
        tmp = tempfile.TemporaryDirectory(prefix="aiterprise-bench-")
        work = Path(tmp.name)
    try:
        res = run(work, args.files, [args.exe] if args.exe else None, online=args.online)
    finally:
        if tmp is not None:
            tmp.cleanup()
    print(f"tree: {res['files']:,} files, {res['bytes'] / 1e6:.1f} MB "
          f"(Python {res['python']} standard-library sources; {res['platform']})")
    print("mode: " + ("online (OSV and the package registries asked; no SecDB)" if args.online else "offline"))
    print(f"first scan (cold):  {res['seconds'][0]:6.1f} s, exit {res['exit'][0]}")
    print(f"second scan (warm): {res['seconds'][1]:6.1f} s, exit {res['exit'][1]}")
    print(f"planted problems found: {len(killer_demo.EXPECT) - len(res['missed'])}/{len(killer_demo.EXPECT)}")
    if res["peak_rss_mb"] is not None:
        print(f"peak memory of a scan: {res['peak_rss_mb']:.0f} MB")
    if args.json:
        args.json.write_text(json.dumps(res, indent=2), encoding="utf-8")
    found = problems(res, args.check, args.check_warm) if args.check is not None else []
    for p in found:
        print(f"  FAIL  {p}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
