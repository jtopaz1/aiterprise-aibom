"""Scan orchestration: walk → discover → merge → judge → de-duplicate.

A crashing analyzer never kills the scan: it is recorded as an error note and the run exits 2
unless a policy failure (exit 1) already decides the outcome. A source that could not be consulted
(OSV unreachable, an advisory that would not download) makes the scan incomplete: exit 2 as well.
Partial coverage is reported, not hidden ("no match" is not "never checked").
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import bundles, ingest, intel_malicious, registry, sources, textio, vulns
from . import policy as policy_mod
from . import walk as walker
from .cache import Cache
from .model import Component, Finding, ScanResult, merge_components, normalize_name, sort_findings
from .walk import rel_posix


@dataclass
class ScanOptions:
    target: Path | None = None
    boms: list[Path] = field(default_factory=list)
    offline: bool = False
    all_files: bool = False
    agent_configs: bool = False  # also read user-level agent configs on this machine
    imports: bool = True
    secrets: bool = True
    judge: bool = True
    mcp_only: bool = False
    max_vulns: int | None = None
    registry: bool = True  # look direct dependencies up on PyPI / npm (existence, age)
    registry_all: bool = False  # ... and transitive ones too
    secdb: Any = None  # a secdb.Client when this machine holds a SecDB credential
    secdb_skipped: str | None = None  # why SecDB was not consulted (shown in `examined`)
    exclude: list[str] = field(default_factory=list)  # globs on root-relative posix paths
    policy: policy_mod.Policy = field(default_factory=policy_mod.Policy)
    cache: Cache | None = None
    providers: list[Any] = field(default_factory=list)  # BYO-key adapters (`--byo`), see providers/


def _excluded(rel: str, patterns: list[str]) -> bool:
    for pat in patterns:
        pat = pat.replace("\\", "/").strip("/")
        if not pat:
            continue
        if fnmatch.fnmatchcase(rel, pat):  # fnmatch's '*' also crosses '/', so 'tests/**' works
            return True
        if not any(ch in pat for ch in "*?[") and (rel == pat or rel.startswith(pat + "/")):
            return True  # a bare directory name excludes everything below it
    return False


class _Runner:
    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self.errors: list[str] = []

    def step(self, name: str, fn: Callable[[], Any], default: Any = None) -> Any:
        try:
            return fn()
        except Exception as err:  # noqa: BLE001 - an analyzer bug must not end the scan
            self.errors.append(name)
            self.result.examine(name).errors += 1
            self.result.notes.append(f"{name}: analyzer error ({type(err).__name__}: {err}); coverage incomplete")
            return default


def _dedupe(findings: list[Finding]) -> list[Finding]:
    by_fp: dict[str, Finding] = {}
    for f in findings:
        existing = by_fp.get(f.fingerprint)
        if existing is None:
            by_fp[f.fingerprint] = f
            continue
        if f.status == "withdrawn" and existing.status != "withdrawn":
            # a withdrawal (e.g. seen live on OSV) is always later than the claim it retracts
            have = {(e.source, e.record) for e in f.evidence}
            f.evidence += [e for e in existing.evidence if (e.source, e.record) not in have]
            by_fp[f.fingerprint] = f
            continue
        seen = {(e.source, e.record) for e in existing.evidence}
        for e in f.evidence:
            if (e.source, e.record) not in seen:
                existing.evidence.append(e)
                seen.add((e.source, e.record))
        existing.confidence = max(existing.confidence, f.confidence)
        existing.kev = existing.kev or f.kev
        for tag in f.maps_to:
            if tag not in existing.maps_to:
                existing.maps_to.append(tag)
    return list(by_fp.values())


def _drop_shadowed_secrets(findings: list[Finding]) -> list[Finding]:
    """The generic secrets pass and the MCP analyzer both see a key hard-coded in an agent config.
    Keep the MCP one (it names the server) and drop the anonymous duplicate for the same file."""
    attributed = {
        (f.rule_id, f.location.path if f.location else "", f.discriminator)
        for f in findings
        if f.rule_id.startswith("ait.secret.") and f.component is not None
    }
    return [
        f for f in findings
        if not (
            f.rule_id.startswith("ait.secret.")
            and f.component is None
            and (f.rule_id, f.location.path if f.location else "", f.discriminator) in attributed
        )
    ]


def _fold_imports(components: list[Component]) -> list[Component]:
    """An import of a package that a manifest/lockfile/BOM already declares is the same component:
    keep the declared one (it has the version) and record where it is imported."""
    declared: dict[tuple, Component] = {}
    for c in components:
        if c.ctype == "library" and c.source not in ("import", "config") and c.ecosystem:
            declared.setdefault((c.ecosystem, normalize_name(c.name, c.ecosystem)), c)
    out: list[Component] = []
    for c in components:
        if c.source == "import" and c.ecosystem:
            host = declared.get((c.ecosystem, normalize_name(c.name, c.ecosystem)))
            if host is not None:
                imported = host.properties.setdefault("imported_at", [])
                for loc in c.locations:
                    if str(loc) not in imported:
                        imported.append(str(loc))
                continue
        out.append(c)
    return out


def _ingest_boms(paths: list[Path], root: Path | None, run: _Runner, explicit: bool) -> list[Component]:
    comps, failed = ingest.ingest_boms(paths, root, run.result, explicit)
    if failed:
        run.errors.append("bom")  # the scan is incomplete: exit 2
    return comps


def run_scan(opts: ScanOptions) -> ScanResult:
    with textio.read_once():  # the analyzers share one read of each file
        return _run_scan(opts)


def _run_scan(opts: ScanOptions) -> ScanResult:
    t0 = time.monotonic()
    started = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if opts.target:
        target_label = str(opts.target)
    elif opts.boms:
        target_label = ", ".join(str(b) for b in opts.boms)
    else:
        target_label = "agent-configs" if opts.agent_configs else ""
    result = ScanResult(target=target_label, mode="offline" if opts.offline else "online", started_at=started)
    result.policy_path = opts.policy.path
    run = _Runner(result)
    try:
        act = bundles.active()
        result.release_id = act[0] if act else None
    except bundles.BundleError as err:  # a pin that cannot be honoured; the CLI stops before this
        result.notes.append(f"definitions: {err}")
        run.errors.append("definitions")
    components: list[Component] = []
    findings: list[Finding] = []
    examined_archives: list[tuple[str, Path]] = []  # for the BYO providers: looked up by file hash

    root: Path | None = None
    files: list[Path] = []
    if opts.target is not None:
        target = opts.target.resolve()
        if not target.exists():
            raise FileNotFoundError(f"scan target does not exist: {opts.target}")
        root = target if target.is_dir() else target.parent
        if target.is_file():
            files = [target]
        else:
            cap = walker.DEFAULT_MAX_FILES
            files = walker.walk(target, all_files=opts.all_files, max_files=cap)
            if len(files) >= cap:
                result.notes.append(f"walk: stopped at the cap of {cap:,} files; files beyond it were not "
                                    "examined")
        if opts.exclude:
            files = [f for f in files if not _excluded(rel_posix(f, root), opts.exclude)]
        result.files_walked = len(files)

    if root is not None and not opts.mcp_only:
        from . import discover, licences, modelfiles, prompts, secrets, services, skills

        manifest_gaps: list[Finding] = []
        components += run.step(sources.DISCOVER.name,
                               lambda: discover.discover_packages(root, files, manifest_gaps), [])
        findings += manifest_gaps
        if opts.imports:
            components += run.step(sources.IMPORTS.name, lambda: discover.discover_imports(root, files), [])
        mc, mf = run.step(sources.MODEL_FILES.name, lambda: modelfiles.analyze(root, files, result), ([], []))
        components += mc
        findings += mf
        components += run.step(sources.MODEL_REFS.name, lambda: licences.discover_model_refs(root, files), [])
        components += run.step(sources.PROMPTS.name, lambda: prompts.discover_prompts(root, files), [])
        components += run.step(sources.AI_SERVICES.name, lambda: services.discover_services(root, files), [])
        sc, sf = run.step(sources.SKILLS.name, lambda: skills.analyze_skills(root, files, result), ([], []))
        components += sc
        findings += sf
        from . import archives

        ac, af = run.step(sources.ARCHIVES.name,
                          lambda: archives.analyze(root, files, result, examined_archives), ([], []))
        components += ac
        findings += af
        if opts.secrets:
            findings += run.step(sources.SECRETS.name, lambda: secrets.scan_secrets(root, files, result), [])
        bom_files = ingest.find_bom_files(files)
        if opts.target is not None and opts.target.is_file() and opts.target.suffix.lower() == ".json":
            bom_files = list(dict.fromkeys(bom_files + [opts.target.resolve()]))
        components += _ingest_boms(bom_files, root, run, explicit=False)

    if opts.boms:
        components += _ingest_boms(opts.boms, root, run, explicit=True)

    if root is not None or opts.agent_configs:
        from . import mcp

        if root is not None:
            mc_, mf_ = run.step(sources.MCP.name, lambda: mcp.analyze_mcp(
                root, files, include_machine=opts.agent_configs, result=result), ([], []))
        else:
            mc_, mf_ = run.step(sources.MCP.name, lambda: mcp.analyze_machine_configs(result), ([], []))
        components += mc_
        findings += mf_
        from . import skills

        if opts.mcp_only and root is not None:
            sc, sf = run.step(sources.SKILLS.name, lambda: skills.analyze_skills(root, files, result), ([], []))
            components += sc
            findings += sf
        if opts.agent_configs:  # the skills folders of the machine, beside its agent configs
            sc, sf = run.step(sources.SKILLS.name, lambda: skills.analyze_machine_skills(result), ([], []))
            components += sc
            findings += sf

    merged = _fold_imports(merge_components(components))
    by_key = {c.key(): c for c in merged}
    result.components = merged

    if opts.judge:
        findings += run.step(sources.AIT_MALICIOUS.name, lambda: intel_malicious.judge(merged, result), [])
        client = vulns.OSVClient(cache=opts.cache or Cache(), offline=opts.offline)
        findings += run.step(sources.OSV.name, lambda: vulns.judge(merged, result, client, opts.max_vulns), [])
        reg = registry.RegistryClient(cache=opts.cache or Cache(), offline=opts.offline or not opts.registry)
        findings += run.step(sources.REGISTRY.name,
                             lambda: registry.judge(merged, result, reg, opts.registry_all), [])
        if not opts.registry and not opts.offline:
            result.examine(sources.REGISTRY.name).skipped = "disabled (--no-registry)"
        if opts.secdb is not None and not opts.offline:
            from . import secdb

            findings += run.step(sources.SECDB.name, lambda: secdb.enrich(merged, result, opts.secdb), [])
        elif opts.secdb_skipped and not opts.offline:
            result.examine(sources.SECDB.name).skipped = opts.secdb_skipped
        if not opts.mcp_only:
            from . import licences

            findings += run.step(
                sources.LICENCES.name,
                lambda: licences.judge_licences(
                    merged,
                    opts.policy.use_context,
                    allow=opts.policy.allow_model_licences or None,
                    deny=opts.policy.deny_model_licences or None,
                    result=result,
                ),
                [],
            )
        findings += policy_mod.denied_package_findings(merged, opts.policy, result)
        if opts.providers:
            # last, so our own findings decide which files the lookup budget goes to; `--offline`
            # is handled inside (no call, and the report says so)
            from . import providers

            findings += run.step(sources.PROVIDERS.name, lambda: providers.enrich(
                opts.providers, merged, list(findings), result, examined_archives, opts.offline), [])

    for f in findings:
        if f.component is not None:
            f.component = by_key.get(f.component.key(), f.component)
    result.findings = sort_findings(_dedupe(_drop_shadowed_secrets(findings)))
    # files of the release that were not used (changed on disk, missing): the wheel's copy stood in
    result.notes.extend(f"definitions: {w}" for w in dict.fromkeys(bundles.WARNINGS))
    result.duration_s = time.monotonic() - t0
    if run.errors or any(ex.errors for ex in result.examined.values()):
        result.exit_code = 2
    return result
