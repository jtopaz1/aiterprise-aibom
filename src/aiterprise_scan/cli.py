"""`aiterprise-scan` command line (design doc 13 §4.6). Exit codes: 0 clean, 1 policy failure, 2 error."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import TOOL_NAME, __version__, bom, html_report, intel_malicious, report, vulns
from . import policy as policy_mod
from .cache import Cache
from .model import ScanResult
from .scanner import ScanOptions, run_scan

COMMANDS = {"scan", "mcp", "bom", "policy", "defs", "version"}
FORMATS = ("table", "json", "sarif", "cyclonedx", "html")
_OUT_NAMES = {"table": "report.txt", "json": "report.json", "sarif": "report.sarif", "cyclonedx": "aibom.cdx.json",
              "html": "report.html"}


def defs_line() -> str:
    snap = intel_malicious.load_snapshot()
    kev = vulns.kev_catalog()
    mal = f"malicious {snap.record_count:,} records" + (f" @{snap.generated_at[:10]}" if snap.generated_at else "")
    kev_txt = f"KEV {kev.get('count', 0):,} CVEs" if kev.get("count") else "KEV not built"
    return f"defs: bundled ({mal} · {kev_txt})"


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", action="append", choices=FORMATS, help="report format (repeatable; default table)")
    p.add_argument("--out", type=Path, help="write reports into this directory instead of stdout")
    p.add_argument("--emit-bom", type=Path, metavar="FILE", help="also write the CycloneDX AI-BOM to FILE")
    p.add_argument("--cdx-version", choices=bom.SUPPORTED_SPEC_VERSIONS, default="1.7")
    p.add_argument("--inventory", action="store_true", help="list every discovered component in the table")
    p.add_argument("--show-suppressed", action="store_true", help="show suppressed and baselined findings")


def _add_gate_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info", "none"],
                   help="exit 1 if any new finding is at least this severe (default: policy, else high)")
    p.add_argument("--policy", type=Path, help="policy file (default: aibom.policy.yaml in the target)")
    p.add_argument("--snyk", type=Path, metavar="FILE", help="import suppressions from a .snyk file")
    p.add_argument("--baseline", type=Path, help="only findings not in this baseline fail the gate")
    p.add_argument("--write-baseline", type=Path, metavar="FILE", help="write current findings as a baseline")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="AIterprise AIBOM Scanner — discover AI components, judge them, emit an AI-BOM.",
    )
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = ap.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a repository, directory, model file or BOM")
    scan.add_argument("target", nargs="?", default=None, type=Path,
                      help="directory or file to scan (default: current directory, unless --bom is given)")
    scan.add_argument("--bom", action="append", type=Path, default=[], help="judge this CycloneDX/SPDX file")
    scan.add_argument("--offline", action="store_true", help="bundled definitions and cache only; no network")
    scan.add_argument("--all-files", action="store_true", help="do not honour .gitignore")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="skip paths matching GLOB (relative to the target; repeatable), e.g. 'tests/**'")
    scan.add_argument("--agent-configs", action="store_true", help="also read this machine's agent/MCP configs")
    scan.add_argument("--no-imports", action="store_true", help="skip manifest-free import discovery")
    scan.add_argument("--no-secrets", action="store_true", help="skip the secret scan")
    scan.add_argument("--max-vulns", type=int, help="at most N advisory findings per component")
    _add_output_args(scan)
    _add_gate_args(scan)

    mcp = sub.add_parser("mcp", help="judge MCP servers and agent skills only; `mcp serve` runs the MCP tool")
    mcp.add_argument("action", nargs="?", choices=["serve"],
                     help="serve: expose scan_ai_supply_chain as a local stdio MCP server")
    mcp.add_argument("--path", type=Path, help="directory to search for project-level configs")
    mcp.add_argument("--agent-configs", action="store_true", help="read this machine's agent/MCP configs")
    mcp.add_argument("--offline", action="store_true")
    _add_output_args(mcp)
    _add_gate_args(mcp)

    b = sub.add_parser("bom", help="emit an AI-BOM without risk judgement (fast compliance mode)")
    b.add_argument("target", nargs="?", default=".", type=Path)
    b.add_argument("--out", type=Path, help="output file (default stdout)")
    b.add_argument("--cdx-version", choices=bom.SUPPORTED_SPEC_VERSIONS, default="1.7")
    b.add_argument("--all-files", action="store_true")

    pol = sub.add_parser("policy", help="policy file tools")
    pol_sub = pol.add_subparsers(dest="policy_command")
    lint = pol_sub.add_parser("lint", help="validate a policy file")
    lint.add_argument("file", nargs="?", type=Path, default=None)

    defs = sub.add_parser("defs", help="definition data status")
    defs_sub = defs.add_subparsers(dest="defs_command")
    defs_sub.add_parser("status", help="show bundled definition data")

    sub.add_parser("version", help="print the version")
    return ap


def _load_policy(args: argparse.Namespace, root: Path | None) -> policy_mod.Policy:
    path = args.policy or (policy_mod.find_policy(root) if root is not None else None)
    pol = policy_mod.load_policy(path) if path else policy_mod.Policy()
    if pol.errors:
        raise SystemExit(_die(f"policy {path}: " + "; ".join(pol.errors)))
    for w in pol.warnings:
        print(f"warning: policy {path}: {w}", file=sys.stderr)
    if getattr(args, "snyk", None):
        pol.suppressions.extend(policy_mod.load_snyk(args.snyk))
    if args.fail_on:
        pol.fail_on = policy_mod.threshold_set(args.fail_on)
    return pol


def _die(msg: str) -> int:
    print(f"{TOOL_NAME}: error: {msg}", file=sys.stderr)
    return 2


def _emit(result: ScanResult, args: argparse.Namespace) -> None:
    formats = args.format or ["table"]
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
    for fmt in formats:
        if fmt == "table":
            if args.out:
                with open(args.out / _OUT_NAMES[fmt], "w", encoding="utf-8") as fh:
                    report.render_table(result, fh, args.inventory, args.show_suppressed, defs_line())
            else:
                report.render_table(result, sys.stdout, args.inventory, args.show_suppressed, defs_line())
            continue
        text = {
            "json": lambda: report.dumps_json(result),
            "sarif": lambda: report.dumps_sarif(result),
            "cyclonedx": lambda: bom.dumps(result, args.cdx_version),
            "html": lambda: html_report.render(result),
        }[fmt]()
        if args.out:
            (args.out / _OUT_NAMES[fmt]).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    if args.out:
        print(f"reports written to {args.out}", file=sys.stderr)
    if args.emit_bom:
        args.emit_bom.parent.mkdir(parents=True, exist_ok=True)
        args.emit_bom.write_text(bom.dumps(result, args.cdx_version), encoding="utf-8")
        print(f"AI-BOM written to {args.emit_bom}", file=sys.stderr)


def _gate(result: ScanResult, pol: policy_mod.Policy, args: argparse.Namespace) -> int:
    baseline_path = args.baseline
    if baseline_path is None and pol.baseline and result.target and Path(result.target).is_dir():
        candidate = Path(result.target) / pol.baseline
        baseline_path = candidate if candidate.is_file() else None
    baseline = policy_mod.load_baseline(baseline_path) if baseline_path else None
    failing = policy_mod.apply(result, pol, baseline)
    if args.write_baseline:
        n = policy_mod.write_baseline(result, args.write_baseline)
        print(f"baseline written to {args.write_baseline} ({n} findings)", file=sys.stderr)
    if failing:
        result.exit_code = 1
    return result.exit_code


def cmd_scan(args: argparse.Namespace) -> int:
    # `scan --bom FILE` judges that BOM only; a directory is walked only when named or when no
    # BOM is given (then the current directory)
    target: Path | None = args.target if args.target is not None else (None if args.bom else Path("."))
    if target is not None and not target.exists():
        return _die(f"scan target does not exist: {target}")
    for b in args.bom:
        if not b.is_file():
            return _die(f"BOM file does not exist: {b}")
    if target is None:
        policy_root = Path(".")
    else:
        policy_root = target if target.is_dir() else target.parent
    pol = _load_policy(args, policy_root)
    opts = ScanOptions(
        target=target,
        boms=list(args.bom),
        offline=args.offline,
        all_files=args.all_files,
        agent_configs=args.agent_configs,
        imports=not args.no_imports,
        secrets=not args.no_secrets,
        max_vulns=args.max_vulns,
        exclude=list(args.exclude),
        policy=pol,
        cache=Cache(),
    )
    result = run_scan(opts)
    code = _gate(result, pol, args)
    _emit(result, args)
    return code


def cmd_mcp(args: argparse.Namespace) -> int:
    if args.action == "serve":
        from . import mcpserver

        return mcpserver.serve()
    if args.path is None and not args.agent_configs:
        args.path = Path(".")
    if args.path is not None and not args.path.is_dir():
        return _die(f"not a directory: {args.path}")
    pol = _load_policy(args, args.path)
    opts = ScanOptions(
        target=args.path,
        offline=args.offline,
        agent_configs=args.agent_configs,
        mcp_only=True,
        policy=pol,
        cache=Cache(),
    )
    result = run_scan(opts)
    code = _gate(result, pol, args)
    _emit(result, args)
    return code


def cmd_bom(args: argparse.Namespace) -> int:
    if not args.target.exists():
        return _die(f"target does not exist: {args.target}")
    result = run_scan(ScanOptions(target=args.target, all_files=args.all_files, judge=False, secrets=False,
                                  offline=True))
    text = bom.dumps(result, args.cdx_version, include_findings=False)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"AI-BOM written to {args.out} ({len(result.components)} components)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 2 if result.exit_code == 2 else 0


def cmd_policy(args: argparse.Namespace) -> int:
    if args.policy_command != "lint":
        return _die("usage: aiterprise-scan policy lint [FILE]")
    path = args.file or policy_mod.find_policy(Path("."))
    if path is None or not path.is_file():
        return _die("no policy file found (aibom.policy.yaml)")
    pol = policy_mod.load_policy(path)
    for w in pol.warnings:
        print(f"warning: {w}")
    for e in pol.errors:
        print(f"error: {e}")
    if pol.errors:
        return 1
    print(f"{path}: OK · use_context={pol.use_context} · fail_on={','.join(sorted(pol.fail_on)) or 'none'} · "
          f"{len(pol.suppressions)} suppression(s)")
    return 0


def cmd_defs(args: argparse.Namespace) -> int:
    snap = intel_malicious.load_snapshot()
    kev = vulns.kev_catalog()
    by_eco = snap.records_by_ecosystem()
    print(f"malicious-versions: {snap.record_count:,} records over {len(snap.records):,} packages "
          f"({', '.join(f'{e} {n:,}' for e, n in sorted(by_eco.items()))}); "
          f"{snap.version_count:,} listed versions, {snap.all_versions_count:,} every-version records; "
          f"generated {snap.generated_at}")
    print(f"  source: {snap.source}")
    for inp in snap.inputs:
        if "sha256" in inp:
            print(f"  input: {inp.get('source', '')} {'/'.join(inp.get('ecosystems', []))} {inp.get('file', '')} "
                  f"sha256 {inp['sha256'][:16]}… ({inp.get('records', 0):,} records)")
        elif "ids" in inp:
            print(f"  input: {inp.get('api', '')} {len(inp['ids'])} ids")
    if kev.get("count"):
        print(f"kev: {kev['count']:,} CVEs, catalog {kev.get('catalog_version') or 'unknown version'}"
              + (f" (released {kev['date_released'][:10]})" if kev.get("date_released") else ""))
    else:
        print("kev: not built — run tools/build_kev.py (KEV upgrades are skipped until then)")
    from . import data

    for name in ("taxonomy.json", "command-rules.json", "poison-patterns.json", "model-rules.json",
                 "licence-verdicts.json"):
        if not data.exists(name):
            print(f"{name}: missing")
            continue
        doc = data.load(name)
        version = doc.get("version") if isinstance(doc, dict) else None
        rules = doc.get("rules") if isinstance(doc, dict) else None
        count = f", {len(rules)} rules" if isinstance(rules, list) else ""
        print(f"{name}: present" + (f", version {version}" if version else "") + count)
    print("signed bundles: not yet served by SecDB (AIT/ait-bundle); definitions bundled in the wheel are in use")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "scan")  # `aiterprise-scan .` is the main command
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "mcp":
            return cmd_mcp(args)
        if args.command == "bom":
            return cmd_bom(args)
        if args.command == "policy":
            return cmd_policy(args)
        if args.command == "defs":
            return cmd_defs(args)
        if args.command == "version":
            print(f"{TOOL_NAME} {__version__}")
            return 0
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    except (FileNotFoundError, PermissionError) as err:
        return _die(str(err))
    except KeyboardInterrupt:
        return 2
    return _die(f"unknown command {args.command}")


if __name__ == "__main__":
    sys.exit(main())
