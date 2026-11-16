"""Registry facts about declared packages (design doc 13 §5.3, AI-M1 "age/existence checks").

Online, each *direct* PyPI/npm dependency is looked up on its public registry:

- does not exist → `ait.pkg.nonexistent` (high): anyone can register the name and the next install
  fetches their code — the slopsquat risk of AI-suggested names, and dependency confusion;
- npm replaced it with a `0.0.1-security` holder → `ait.pkg.security-holder` (critical, malicious):
  npm removed the package for security reasons;
- first published < 72 h ago → `ait.pkg.new-package` (medium); most malicious packages are classified
  within about three days, so a brand-new dependency has had no scrutiny yet;
- the pinned version is not on the registry → `ait.pkg.version-missing` (medium); registries remove
  malicious releases.

Offline and online, `ait.pkg.typosquat` (medium) compares names with widely used and AI packages.

Privacy: registry lookups are GET requests, so the registry sees the package *name* (never paths,
versions of other packages or source). `--offline` and `--no-registry` send nothing. Transitive
dependencies and packages installed from a URL or a private index are not queried.
"""

from __future__ import annotations

import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable
from urllib.parse import quote

from . import data, net, sources, taxonomy
from .cache import Cache
from .model import OWASP_SUPPLY_CHAIN, Component, Evidence, Finding, ScanResult, normalize_name
from .versions import versions_equal

NEW_PACKAGE_HOURS = 72
NPM_FULL_DOC_MAX_VERSIONS = 5  # only young packages need the (large) full document for publish times
WORKERS = 8
PYPI_SIMPLE = "https://pypi.org/simple/{}/"
NPM_REGISTRY = "https://registry.npmjs.org/{}"
REGISTRY_NAMES = {"pypi": "PyPI", "npm": "npm"}

Fetch = Callable[[str, dict], Any]


def _default_fetch(url: str, headers: dict) -> Any:
    return net.request_json("GET", url, headers=headers, timeout=20.0)


@dataclass
class RegistryClient:
    cache: Cache
    offline: bool = False
    fetch: Fetch | None = None  # None: the live registry (looked up at call time, so tests can patch it)
    now: Callable[[], dt.datetime] = field(default=lambda: dt.datetime.now(dt.timezone.utc))

    def _get(self, namespace: str, url: str, headers: dict) -> dict | None:
        """The document, None when the registry says 404, NetError otherwise."""
        cached = self.cache.get(namespace, url)
        if cached is not None:
            return cached.get("doc")
        try:
            doc = (self.fetch or _default_fetch)(url, headers)
        except net.NetError as err:
            if err.status == 404:
                self.cache.put(namespace, url, {"doc": None})
                return None
            raise
        self.cache.put(namespace, url, {"doc": doc})
        return doc

    def pypi(self, name: str) -> dict | None:
        url = PYPI_SIMPLE.format(quote(normalize_name(name, "pypi"), safe=""))
        return self._get("pypi-simple", url, {"Accept": "application/vnd.pypi.simple.v1+json"})

    def npm(self, name: str, full: bool = False) -> dict | None:
        url = NPM_REGISTRY.format(quote(name, safe="@"))
        accept = "application/json" if full else "application/vnd.npm.install-v1+json"
        return self._get("npm-full" if full else "npm-abbrev", url, {"Accept": accept})


# --------------------------------------------------------------------------------------------
# Registry facts
# --------------------------------------------------------------------------------------------

@dataclass
class Facts:
    exists: bool
    versions: list[str] = field(default_factory=list)
    created: dt.datetime | None = None
    version_times: dict[str, dt.datetime] = field(default_factory=dict)
    security_holder: bool = False
    url: str = ""


def _ts(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


_ARCHIVE_EXTS = (".tar.gz", ".tar.bz2", ".tgz", ".zip", ".whl", ".egg")


def _pypi_file_version(filename: str, name: str) -> str | None:
    """Version of a PyPI release file: wheels are <dist>-<version>-<tags>.whl, sdists <name>-<version>."""
    low = filename.lower()
    ext = next((e for e in _ARCHIVE_EXTS if low.endswith(e)), None)
    if ext is None:
        return None
    base = filename[: -len(ext)]
    if ext in (".whl", ".egg"):
        parts = base.split("-")
        dist, ver = (parts[0], parts[1]) if len(parts) > 1 else (base, "")
    else:
        dist, _, ver = base.rpartition("-")
    if not ver or normalize_name(dist, "pypi") != normalize_name(name, "pypi"):
        return None
    return ver


def pypi_facts(doc: dict, name: str) -> Facts:
    files = doc.get("files") if isinstance(doc.get("files"), list) else []
    times: dict[str, dt.datetime] = {}
    first: dt.datetime | None = None
    for f in files:
        if not isinstance(f, dict):
            continue
        when = _ts(f.get("upload-time"))
        if when is None:
            continue
        first = when if first is None or when < first else first
        ver = _pypi_file_version(str(f.get("filename", "")), name)
        if ver and (ver not in times or when < times[ver]):
            times[ver] = when
    versions = [str(v) for v in doc.get("versions") or []] or sorted(times)
    return Facts(True, versions, first, times, url=f"https://pypi.org/project/{normalize_name(name, 'pypi')}/")


def npm_facts(abbrev: dict, full: dict | None, name: str) -> Facts:
    versions = sorted((abbrev.get("versions") or {}).keys()) if isinstance(abbrev.get("versions"), dict) else []
    times: dict[str, dt.datetime] = {}
    created = None
    if isinstance(full, dict) and isinstance(full.get("time"), dict):
        created = _ts(full["time"].get("created"))
        for k, v in full["time"].items():
            if k not in ("created", "modified") and (when := _ts(v)):
                times[k] = when
    holder = versions == ["0.0.1-security"]
    return Facts(True, versions, created, times, security_holder=holder, url=f"https://www.npmjs.com/package/{name}")


# --------------------------------------------------------------------------------------------
# Typosquat names
# --------------------------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _popular() -> tuple[dict[str, dict[str, str]], dict[str, set[str]]]:
    """({ecosystem: {comparison key: display name}}, {ecosystem: legit near names})."""
    doc = data.load("popular-packages.json")
    names: dict[str, dict[str, str]] = {}
    for eco, pkgs in doc.get("packages", {}).items():
        for p in pkgs:
            names.setdefault(eco, {})[_key(p, eco)] = p
    for eco in ("pypi", "npm"):
        for p in taxonomy._libraries().get(eco, {}):
            names.setdefault(eco, {}).setdefault(_key(p, eco), p)
    legit = {eco: {_key(p, eco) for p in v} for eco, v in doc.get("legit_near", {}).items()}
    return names, legit


def _key(name: str, eco: str) -> str:
    return normalize_name(name, eco) if eco == "pypi" else name.lower()


def _damerau(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def looks_like(name: str, eco: str) -> str | None:
    """The popular package this name imitates, or None."""
    popular, legit = _popular()
    targets = popular.get(eco, {})
    key = _key(name, eco)
    if key in targets or key in legit.get(eco, set()) or len(key) < 5:
        return None
    flat = key.replace("-", "").replace("_", "").replace(".", "")
    for tkey, display in targets.items():
        if len(tkey) < 5:
            continue
        if flat == tkey.replace("-", "").replace("_", "").replace(".", ""):
            return display  # separator games: open-ai / openai, py-yaml / pyyaml
        limit = 2 if len(tkey) >= 10 else 1
        if _damerau(key, tkey, limit) <= limit:
            return display
    return None


# --------------------------------------------------------------------------------------------
# Judgement
# --------------------------------------------------------------------------------------------

def _queryable(comp: Component) -> bool:
    return not comp.properties.get("url") and not comp.properties.get("index")


def _hours(now: dt.datetime, then: dt.datetime) -> int:
    return max(0, int((now - then).total_seconds() // 3600))


def _finding(rule: str, sev: str, verdict: str, conf: int, comp: Component, title: str, remediation: str,
             source: str, url: str, detail: dict) -> Finding:
    return Finding(rule_id=rule, title=title, severity=sev, verdict=verdict, confidence=conf, component=comp,
                   evidence=[Evidence(source, rule.rsplit(".", 1)[-1], url, detail)], remediation=remediation,
                   maps_to=[OWASP_SUPPLY_CHAIN])


def facts_findings(comp: Component, facts: Facts | None, now: dt.datetime) -> list[Finding]:
    eco = comp.ecosystem or ""
    reg = REGISTRY_NAMES.get(eco, eco)
    src = "pypi" if eco == "pypi" else "npm-registry"
    if facts is None:
        return [_finding(
            "ait.pkg.nonexistent", "high", "suspicious", 85, comp,
            f"{comp.name} does not exist on {reg}; anyone can register it, and the next install fetches their code",
            "Check the name: AI assistants invent package names, and attackers register them (slopsquatting). "
            "If this is an internal package, install it from your private index with the index pinned "
            "(pip --index-url, an .npmrc scope) and list it under allow_packages.",
            src, PYPI_SIMPLE.format(normalize_name(comp.name, "pypi")) if eco == "pypi" else NPM_REGISTRY.format(comp.name),
            {"registry": reg, "status": 404})]
    out: list[Finding] = []
    if facts.security_holder:
        out.append(_finding(
            "ait.pkg.security-holder", "critical", "malicious", 90, comp,
            f"npm removed {comp.name} for security reasons (only a 0.0.1-security holder remains)",
            "Remove the dependency; assume any environment that installed it is compromised and rotate its credentials.",
            src, facts.url, {"registry": reg, "versions": facts.versions}))
        return out
    if facts.created is not None and (age := _hours(now, facts.created)) < NEW_PACKAGE_HOURS:
        out.append(_finding(
            "ait.pkg.new-package", "medium", "suspicious", 70, comp,
            f"{comp.name} was first published {age} hours ago on {reg}; it has had no community scrutiny yet",
            "Wait until the package is a few days old, or review its code and maintainer before installing it.",
            src, facts.url, {"registry": reg, "first_published": facts.created.isoformat(), "age_hours": age}))
    if comp.version and facts.versions and not any(versions_equal(eco, comp.version, v) for v in facts.versions):
        out.append(_finding(
            "ait.pkg.version-missing", "medium", "suspicious", 65, comp,
            f"{comp.name} {comp.version} is not on {reg}; registries remove malicious and broken releases",
            "Find out why the release was removed before keeping it; move to a version that is published.",
            src, facts.url, {"registry": reg, "pinned": comp.version, "published_versions": len(facts.versions)}))
    return out


def typosquat_findings(comp: Component) -> list[Finding]:
    target = looks_like(comp.name, comp.ecosystem or "")
    if not target:
        return []
    return [_finding(
        "ait.pkg.typosquat", "medium", "suspicious", 55, comp,
        f"{comp.name} looks like the widely used package {target}; check that this is the package you meant",
        f"If you meant {target}, fix the name. Lookalike names are a common way to slip malware into dependencies.",
        "ait-rules", None, {"looks_like": target, "fp_rate_measured": None})]


def _lookup(client: RegistryClient, comp: Component) -> Facts | None:
    if comp.ecosystem == "pypi":
        doc = client.pypi(comp.name)
        return None if doc is None else pypi_facts(doc, comp.name)
    abbrev = client.npm(comp.name)
    if abbrev is None:
        return None
    versions = abbrev.get("versions") if isinstance(abbrev.get("versions"), dict) else {}
    full = client.npm(comp.name, full=True) if len(versions) <= NPM_FULL_DOC_MAX_VERSIONS else None
    return npm_facts(abbrev, full, comp.name)


def judge(components: list[Component], result: ScanResult, client: RegistryClient,
          everything: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    libs = [c for c in components if c.ctype == "library" and c.ecosystem in REGISTRY_NAMES
            and c.source not in ("import",)]
    for comp in libs:
        findings += typosquat_findings(comp)
    examined = result.examine(sources.REGISTRY.name)
    if client.offline:
        examined.skipped = "offline"
        return findings
    seen: dict[tuple, list[Component]] = {}
    transitive = 0
    for comp in libs:
        if not _queryable(comp):
            continue
        if not everything and comp.properties.get("direct") is False:
            transitive += 1
            continue
        seen.setdefault((comp.ecosystem, normalize_name(comp.name, comp.ecosystem)), []).append(comp)
    if transitive:
        result.notes.append(f"registry: {transitive} transitive package(s) not looked up on their registry "
                            "(direct dependencies only; they were resolved by your lockfile)")
    now = client.now()

    def one(item):
        key, comps = item
        try:
            return key, comps, _lookup(client, comps[0]), None
        except net.NetError as err:
            return key, comps, None, err

    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for key, comps, facts, err in pool.map(one, sorted(seen.items())):
            if err is not None:
                examined.errors += 1
                errors.append(f"{key[1]} ({err})")
                continue
            examined.checked += 1
            examined.with_data += 1
            for comp in comps:
                findings += facts_findings(comp, facts, now)
    if errors:
        result.notes.append(f"registry: {len(errors)} lookup(s) failed — existence and age UNVERIFIED, not safe: "
                            + "; ".join(errors[:3]) + (" …" if len(errors) > 3 else ""))
    return findings
