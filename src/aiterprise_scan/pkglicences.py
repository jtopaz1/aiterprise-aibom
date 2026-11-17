"""Package licences (design doc 13 §5.3: "package licences from manifest + deps.dev").

Offline, a package's licence is what the file that lists it records: npm lockfiles (v2 and v3) carry
each package's `license` (`discover`). Online, each pinned PyPI or npm package still without one is
looked up on deps.dev's version endpoint (one GET per name and version, cached like the registry
answers): the licences that version declares, as SPDX expressions. Several mean they all apply, so
they are joined with AND. A licence deps.dev cannot map to SPDX comes back as "non-standard"; the
BOM leaves it empty rather than record a word that names no licence, and a note lists those packages.

The licence lands on the component, so the CycloneDX BOM (`licenses`, acknowledged as declared), the
JSON report and the HTML report show it. No verdict is drawn from it here: model and dataset licences
are judged in `licences`.

Privacy: like the registry lookups, a deps.dev lookup is a GET that shows deps.dev a public package's
name and version, nothing else. `--offline` and `--no-registry` send nothing. Packages installed
from a URL or a private index are not looked up.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from . import net, sources
from .model import Component, ScanResult, normalize_name
from .registry import DEPS_DEV_SYSTEMS, WORKERS, RegistryClient, _queryable

NON_STANDARD = "non-standard"


def licence_of(doc: dict | None) -> str | None:
    """The licence deps.dev records for a version, as one SPDX expression; None when it has none."""
    found = doc.get("licenses") if isinstance(doc, dict) else None
    exprs = [s.strip() for s in found if isinstance(s, str) and s.strip() and s.strip() != NON_STANDARD] \
        if isinstance(found, list) else []
    exprs = list(dict.fromkeys(exprs))
    if len(exprs) <= 1:
        return exprs[0] if exprs else None
    return " AND ".join(f"({e})" if " OR " in e or " AND " in e or " WITH " in e else e for e in exprs)


def _wanted(comp: Component) -> bool:
    # an exact version only: imports never have one, and a range names no single release
    return (comp.ctype == "library" and comp.ecosystem in DEPS_DEV_SYSTEMS and not comp.licence
            and bool(comp.version) and _queryable(comp))


def judge(components: list[Component], result: ScanResult, client: RegistryClient) -> None:
    """Fill in the licence of each pinned PyPI / npm package that has none, from deps.dev."""
    examined = result.examine(sources.DEPS_DEV.name)
    if client.offline:
        examined.skipped = "offline"
        return
    wanted: dict[tuple, list[Component]] = {}
    for comp in components:
        if _wanted(comp):
            key = (comp.ecosystem, normalize_name(comp.name, comp.ecosystem), comp.version)
            wanted.setdefault(key, []).append(comp)

    def one(item):
        (eco, _, version), comps = item
        try:
            return comps, client.depsdev_version(eco, comps[0].name, version), None
        except net.NetError as err:
            return comps, None, err

    errors: list[str] = []
    non_standard: list[str] = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for comps, doc, err in pool.map(one, sorted(wanted.items())):
            label = f"{comps[0].name} {comps[0].version}"
            if err is not None:
                examined.errors += 1
                errors.append(f"{label} ({err})")
                continue
            examined.checked += 1
            licence = licence_of(doc)
            if licence:
                examined.with_data += 1
                for comp in comps:
                    comp.licence = licence
            elif isinstance(doc, dict) and NON_STANDARD in (doc.get("licenses") or []):
                non_standard.append(label)
    if non_standard:
        result.notes.append(
            f"deps.dev: {len(non_standard)} package version(s) declare a licence deps.dev does not map to SPDX "
            f"(\"{NON_STANDARD}\"), so the BOM leaves it empty: " + ", ".join(non_standard[:5])
            + (" …" if len(non_standard) > 5 else ""))
    if errors:
        result.notes.append(f"deps.dev: {len(errors)} licence lookup(s) failed, so the BOM has no licence for them: "
                            + "; ".join(errors[:3]) + (" …" if len(errors) > 3 else ""))
