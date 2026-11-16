"""BYO-key third-party enrichment (design doc 13 §4.6, §6.4, K.8; FD22).

`scan --byo virustotal=ENV_VAR` asks a third-party provider about the model files and package
archives this scan examined, over a direct connection from this machine, with the customer's own
key. No SecDB sign-in is involved and the key never goes anywhere but the provider.

FD22, enforced here and in the callers:
- hash lookups only: an adapter is handed a SHA-256, never a path or file content;
- nothing a provider returns is cached or written to definition data (this package holds no cache
  handle), and no rule is measured or tuned from it (`quality.rule_quality` is always unmeasured);
- provider results stay the provider's: rule ids are `ext.<provider>.*`, titles and evidence name
  the provider, and `without_external` takes them out of anything sent to SecDB or a cloud;
- "no answer" is never "clean": a quota stop (429), a refused key (401/403), a failed call, a file
  over the lookup budget and `--offline` are each reported as not verified with the provider.

Budget: at most `max_lookups` calls per provider and scan, never a sleep, most suspicious files
first (files that already have findings, then pickle-family model files, then the rest). After
any failed call the provider is not called again in that scan.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..model import SEVERITY_RANK, Component, Finding, ScanResult
from .base import EXT_PREFIX, ConfigError, FileTarget, HashProvider, ProviderError, is_external, provider_of
from .virustotal import VirusTotal

# Adding a provider: write its adapter module and name it here. The scanner does not change.
REGISTRY: dict[str, type[HashProvider]] = {VirusTotal.name: VirusTotal}

__all__ = ["EXT_PREFIX", "REGISTRY", "ConfigError", "FileTarget", "HashProvider", "ProviderError", "enrich",
           "from_specs", "is_external", "label_of", "provider_of", "without_external"]


def _available() -> str:
    return ", ".join(sorted(REGISTRY))


def from_specs(specs: list[str], environ: Mapping[str, str] | None = None) -> list[HashProvider]:
    """The adapters named by `--byo PROVIDER=ENV_VAR` values, or ConfigError.

    The part after `=` is the NAME of an environment variable. Nothing from a spec is echoed back:
    it may be a key given by mistake."""
    environ = os.environ if environ is None else environ
    out: list[HashProvider] = []
    for spec in specs:
        name, sep, var = spec.partition("=")
        name, var = name.strip().lower(), var.strip()
        if not sep or not name or not var:
            raise ConfigError("--byo expects PROVIDER=ENV_VAR, where ENV_VAR is the name of an environment "
                              f"variable that holds your key (providers: {_available()})")
        cls = REGISTRY.get(name)
        if cls is None:
            raise ConfigError(f"--byo: unknown provider before '=' (providers: {_available()})")
        if any(p.name == name for p in out):
            raise ConfigError(f"--byo {name} was given more than once")
        key = environ.get(var, "").strip()
        if not key:
            raise ConfigError(f"--byo {name}: the environment variable named after '=' is not set or is empty; "
                              "give the NAME of a variable that holds the key, never the key itself")
        out.append(cls.from_env(key, environ))
    return out


# --------------------------------------------------------------------------------------------
# Scan enrichment
# --------------------------------------------------------------------------------------------

def _rank(severity: int | None, pickle_family: bool, location: str) -> tuple:
    if severity is not None:
        return (0, -severity, location)  # already has findings: worst first
    return (1 if pickle_family else 2, 0, location)


def _targets(components: list[Component], findings: list[Finding],
             archives: Iterable[tuple[str, Path]]) -> list[FileTarget]:
    """The model files and package archives of this scan, most suspicious first."""
    from .. import modelfiles  # the CLI imports this package at start-up; the analyzer only when scanning

    worst: dict[str, int] = {}  # file path -> highest severity of a finding in it
    for f in findings:
        if f.location is None:
            continue
        path = f.location.path
        for key in {path, path.split("!", 1)[0]}:  # a finding in a member also counts for its archive
            worst[key] = max(worst.get(key, -1), SEVERITY_RANK[f.severity])
    out: list[FileTarget] = []
    for c in components:
        if c.ctype != "model-file":
            continue
        loc = str(c.properties.get("path") or (c.locations[0].path if c.locations else c.name))
        pickled = modelfiles.is_pickle_family(c.name, c.properties.get("format"))
        out.append(FileTarget(c.name, loc, sha256=c.hashes.get("sha256"), component=c,
                              rank=_rank(worst.get(loc), pickled, loc)))
    packaged = {c.properties.get("archive"): c for c in components
                if c.ctype == "library" and c.properties.get("archive")}
    for rel, path in archives:
        out.append(FileTarget(path.name, rel, path=path, component=packaged.get(rel),
                              rank=_rank(worst.get(rel), False, rel)))
    return sorted(out, key=lambda t: t.rank)


def _stop(provider: HashProvider, err: ProviderError, examined) -> str:
    """Why the provider is not called again in this scan (the SecDB rule: 429 degrades, an outage
    is an error, and neither is ever read as clean)."""
    if err.status == 429:
        why = "quota reached (HTTP 429)"
    elif err.status in (401, 403):
        why = f"key refused (HTTP {err.status})"
    else:
        examined.errors += 1
        why = f"lookup failed ({err})"
    examined.skipped = why
    return why


def _ask(provider: HashProvider, targets: list[FileTarget], result: ScanResult, offline: bool) -> list[Finding]:
    examined = result.examine(provider.name)
    unverified = f"not verified with {provider.label}"
    if offline:
        examined.skipped = "offline"
        result.notes.append(f"{provider.name}: --offline, no call was made; {len(targets)} file(s) {unverified}")
        return []
    out: list[Finding] = []
    answers: dict[str, Any] = {}  # this scan only, in memory: provider answers are never cached
    used = left = unhashed = unknown = 0
    stopped: str | None = None
    for target in targets:
        if stopped:
            left += 1
            continue
        sha = target.digest()
        if sha is None:
            unhashed += 1
            continue
        if sha not in answers:
            if used >= provider.max_lookups:
                left += 1
                continue
            try:
                answers[sha] = provider.lookup(sha)
            except ProviderError as err:
                stopped = _stop(provider, err, examined)
                left += 1
                continue
            used += 1
        answer = answers[sha]
        examined.checked += 1
        if answer is None:
            unknown += 1
            continue
        examined.with_data += 1
        finding = provider.finding(target, answer)
        if finding is not None:
            out.append(finding)
    if stopped:
        result.notes.append(f"{provider.name}: {stopped}; {left} file(s) {unverified}, not clean")
    elif left:
        result.notes.append(f"{provider.name}: {left} file(s) not checked (budget of {provider.max_lookups} "
                            f"lookup(s) per scan, see {provider.budget_env()}); {unverified}, not clean")
    if unhashed:
        result.notes.append(f"{provider.name}: {unhashed} file(s) could not be hashed; {unverified}, not clean")
    if unknown:
        result.notes.append(f"{provider.name}: {unknown} file hash(es) unknown to {provider.label} (no record, or "
                            "no engine result); unknown is not clean")
    return out


def without_external(doc: dict) -> tuple[dict, dict[str, int]]:
    """An aiterprise-json report without provider results, and how many findings of each provider
    it held. Applied to everything sent to SecDB or a cloud (FD22). The caller's document is not
    changed; the report on this machine keeps the provider findings.

    Out go the `ext.*` findings, the providers' `examined` entries and the notes about them; the
    summary counts are reduced to match."""
    findings = doc.get("findings")
    gone = [f for f in findings if isinstance(f, dict) and is_external(f.get("rule_id"))] \
        if isinstance(findings, list) else []
    kept: dict[str, int] = {}
    for f in gone:
        name = provider_of(f["rule_id"]) or "provider"
        kept[name] = kept.get(name, 0) + 1
    names = set(REGISTRY) | set(kept)

    def about_a_provider(note: Any) -> bool:
        return isinstance(note, str) and any(note.startswith(f"{n}:") or f"{EXT_PREFIX}{n}." in note for n in names)

    out = dict(doc)
    if gone:
        out["findings"] = [f for f in findings if not (isinstance(f, dict) and is_external(f.get("rule_id")))]
    if isinstance(doc.get("examined"), dict):
        out["examined"] = {k: v for k, v in doc["examined"].items() if k not in names}
    if isinstance(doc.get("notes"), list):
        out["notes"] = [n for n in doc["notes"] if not about_a_provider(n)]
    summary = doc.get("summary")
    if gone and isinstance(summary, dict):
        summary = dict(summary)
        severity = dict(summary["severity"]) if isinstance(summary.get("severity"), dict) else {}
        status = dict(summary["status"]) if isinstance(summary.get("status"), dict) else {}
        for f in gone:
            state, sev = f.get("status"), f.get("severity")
            if isinstance(status.get(state), int):
                status[state] -= 1
                if status[state] <= 0:
                    del status[state]
            if state not in ("suppressed", "withdrawn", "resolved") and isinstance(severity.get(sev), int):
                severity[sev] = max(0, severity[sev] - 1)  # `severity` counts active findings only
        if isinstance(summary.get("findings"), int):
            summary["findings"] = max(0, summary["findings"] - len(gone))
        if "severity" in summary:
            summary["severity"] = severity
        if "status" in summary:
            summary["status"] = status
        out["summary"] = summary
    return out, kept


def label_of(name: str) -> str:
    """A provider's name as people write it (`virustotal` -> `VirusTotal`)."""
    cls = REGISTRY.get(name)
    return cls.label if cls is not None else name


def enrich(active: list[HashProvider], components: list[Component], findings: list[Finding], result: ScanResult,
           archives: Iterable[tuple[str, Path]] = (), offline: bool = False) -> list[Finding]:
    """Ask each BYO-key provider about the files of this scan; returns the providers' findings.

    `findings` are the scan's own findings so far (they only order the lookups); `archives` are
    the package archives it examined, as (root-relative path, file)."""
    out: list[Finding] = []
    if not active:
        return out
    targets = _targets(components, findings, archives)
    for provider in active:
        try:
            out += _ask(provider, targets, result, offline)
        except Exception as err:  # noqa: BLE001 - an adapter bug must not end the scan
            # the type only: the text of an unexpected exception could quote a request header
            result.examine(provider.name).errors += 1
            result.notes.append(f"{provider.name}: adapter error ({type(err).__name__}); files not verified "
                                f"with {provider.label}, not clean")
    return out
