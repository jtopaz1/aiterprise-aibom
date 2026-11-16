"""The gated scan: a scan under the project's policy, with its exit code decided.

    gated_scan(options, overrides) -> ScanResult

One place for the gate, for every caller that reports a pass or a failure (the CLI's `scan` and
`mcp`, the MCP tool, the UI):

1. The policy root is the scanned project directory: the target, a file target's parent, or the
   current directory when only a BOM is judged. A scan of this machine's agent configs alone has
   none, so no policy is looked up for it.
2. The policy is the file the caller names, else the one found in the policy root, else the
   defaults. The project's `.aiterprise/suppressions.json` and a `.snyk` file are added to it.
3. A policy that does not load raises `PolicyError` before anything is scanned.
4. SecDB is consulted when this machine holds a credential and the caller did not decline; when it
   is not, the coverage says why.
5. The baseline is the file the caller names, else the policy's `baseline:` under the policy root.
6. Exit code: 1 when a new finding is at or above the threshold; else 2 when the scan is
   incomplete; else 0.

`scanner.run_scan` stays the scan without a gate (`bom`, `tools/measure_fp.py`). GLOSSARY.md
defines the terms.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path

from . import credentials, secdb
from . import policy as policy_mod
from .cache import Cache
from .model import ScanResult
from .scanner import ScanOptions, run_scan

NOT_LOGGED_IN = "not logged in (aiterprise-scan login)"


class PolicyError(Exception):
    """The policy, or the project's suppressions file, does not load. Nothing was scanned."""


@dataclass
class GateOverrides:
    """What a caller may say about the gate. Everything else comes from the project."""

    policy_file: Path | None = None  # instead of the policy found in the policy root
    snyk_file: Path | None = None  # a `.snyk` file whose ignores are imported as suppressions
    fail_on: str | None = None  # a threshold (critical … info, none) instead of the policy's
    baseline_file: Path | None = None  # instead of the policy's `baseline:`
    skip_secdb: str | None = None  # why SecDB must not be consulted; shown in the coverage


def policy_root(opts: ScanOptions) -> Path | None:
    """The scanned project directory: where the policy, the suppressions and the baseline live."""
    if opts.target is not None:
        return opts.target if opts.target.is_dir() else opts.target.parent
    return Path(".") if opts.boms else None


def gated_scan(opts: ScanOptions, overrides: GateOverrides | None = None) -> ScanResult:
    """Scan under the project's policy and decide the exit code. Raises `PolicyError`.

    `opts` says what to scan and how. Its `policy`, `secdb` and `secdb_skipped` belong to the gate
    and are replaced here, whatever the caller put in them."""
    overrides = overrides or GateOverrides()
    root = policy_root(opts)
    pol = _load_policy(root, overrides)
    client, skipped = _secdb(overrides)
    result = run_scan(dataclasses.replace(
        opts, policy=pol, secdb=client, secdb_skipped=skipped,
        cache=opts.cache if opts.cache is not None else Cache()))
    result.notes[:0] = [f"policy {pol.path}: {warning}" for warning in pol.warnings]
    if policy_mod.apply(result, pol, _baseline(root, pol, overrides)):
        result.exit_code = 1  # a policy failure outranks an incomplete scan (2)
    return result


def _load_policy(root: Path | None, overrides: GateOverrides) -> policy_mod.Policy:
    path = overrides.policy_file or (policy_mod.find_policy(root) if root is not None else None)
    pol = policy_mod.load_policy(path) if path else policy_mod.Policy()
    if pol.errors:
        raise PolicyError(f"policy {path}: " + "; ".join(pol.errors))
    if overrides.snyk_file:
        pol.suppressions.extend(policy_mod.load_snyk(overrides.snyk_file))
    policy_mod.merge_local_suppressions(pol, root)
    if pol.errors:
        raise PolicyError("; ".join(pol.errors))
    if overrides.fail_on:
        pol.fail_on = policy_mod.threshold_set(overrides.fail_on)
    return pol


def _secdb(overrides: GateOverrides) -> tuple[secdb.Client | None, str | None]:
    if overrides.skip_secdb:
        return None, overrides.skip_secdb
    cred = credentials.load()
    if cred is None:
        return None, NOT_LOGGED_IN
    return secdb.Client(cred), None


def _baseline(root: Path | None, pol: policy_mod.Policy, overrides: GateOverrides) -> set[str] | None:
    path = overrides.baseline_file
    if path is None and pol.baseline and root is not None and (root / pol.baseline).is_file():
        path = root / pol.baseline
    return policy_mod.load_baseline(path) if path else None
