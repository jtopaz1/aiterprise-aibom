"""Registry facts about declared packages (design doc 13 §5.3, AI-M1 "age/existence checks").

Online, each *direct* PyPI/npm dependency is looked up on its public registry:

- does not exist → `ait.pkg.nonexistent` (high): anyone can register the name and the next install
  fetches their code — the slopsquat risk of AI-suggested names, and dependency confusion;
- npm replaced it with a `0.0.1-security` holder → `ait.pkg.security-holder` (critical, malicious):
  npm removed the package for security reasons;
- first published < 72 h ago → `ait.pkg.new-package` (medium); most malicious packages are classified
  within about three days, so a brand-new dependency has had no scrutiny yet;
- the pinned version is not on the registry → `ait.pkg.version-missing` (medium); registries remove
  malicious releases;
- the release in use (the pinned one, or the newest when nothing is pinned) is under 30 days old and
  came after two years without a release → `ait.pkg.dormant-release` (medium), or its major version
  is 10 or more above every earlier release → `ait.pkg.version-jump` (medium). Both need publish
  times: every PyPI package has them; on npm only packages with at most 5 versions are read in full;
- that recent release is unsigned though the release before it was signed → `ait.pkg.provenance-dropped`
  (medium), or it came from someone new → `ait.pkg.publisher-change` (medium) (design doc 13 C17; see
  `publisher_findings`). These fetch the two releases' manifests (npm) or attestations (PyPI).

Offline and online, `ait.pkg.typosquat` (medium) compares names with widely used and AI packages
(design doc 13 C16) and names the kind of slip: separators, lookalike letters (`rn` for `m`), a
swapped, missing, doubled or adjacent-key letter (US QWERTY). A 4-letter popular name is one
keystroke from many real packages (`xlsx`/`clsx`, `blob`/`glob`) and from many squats, so such a
name is flagged only online, when the registry shows it was first published under a year ago.

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
from .versions import pep440_parse, semver_parse, versions_equal

NEW_PACKAGE_HOURS = 72
NPM_FULL_DOC_MAX_VERSIONS = 5  # only young packages need the (large) full document for publish times
WORKERS = 8
PYPI_SIMPLE = "https://pypi.org/simple/{}/"
NPM_REGISTRY = "https://registry.npmjs.org/{}"
REGISTRY_NAMES = {"pypi": "PyPI", "npm": "npm"}
DEPS_DEV = "https://api.deps.dev/v3/systems/{}/packages/{}/versions/{}"
DEPS_DEV_SYSTEMS = {"pypi": "PYPI", "npm": "NPM"}

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

    def npm_version(self, name: str, version: str) -> dict | None:
        """One version's manifest: who published it (`_npmUser`) and the maintainers at the time."""
        url = NPM_REGISTRY.format(quote(name, safe="@")) + "/" + quote(version, safe="")
        return self._get("npm-version", url, {"Accept": "application/json"})

    def pypi_provenance(self, url: str) -> dict | None:
        """A PEP 740 provenance document (the URL comes from the simple index)."""
        return self._get("pypi-provenance", url, {"Accept": "application/json"})

    def depsdev_version(self, ecosystem: str, name: str, version: str) -> dict | None:
        """deps.dev's record of one PyPI or npm version (its `licenses`), None when it has none."""
        if ecosystem == "pypi":
            name = normalize_name(name, "pypi")
        url = DEPS_DEV.format(DEPS_DEV_SYSTEMS[ecosystem], quote(name, safe=""), quote(version, safe=""))
        return self._get("depsdev-version", url, {"Accept": "application/json"})


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
    attested: dict[str, str] = field(default_factory=dict)  # PyPI: version -> a PEP 740 provenance URL
    latest: str | None = None                                # npm: dist-tags.latest
    modified: dt.datetime | None = None                      # npm: when the package document last changed


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
    attested: dict[str, str] = {}
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
        if ver and isinstance(f.get("provenance"), str) and f["provenance"].startswith("https://"):
            attested.setdefault(ver, f["provenance"])
    versions = [str(v) for v in doc.get("versions") or []] or sorted(times)
    return Facts(True, versions, first, times, url=f"https://pypi.org/project/{normalize_name(name, 'pypi')}/",
                 attested=attested)


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
    tags = abbrev.get("dist-tags") if isinstance(abbrev.get("dist-tags"), dict) else {}
    latest = tags.get("latest") if isinstance(tags.get("latest"), str) else None
    return Facts(True, versions, created, times, security_holder=holder, url=f"https://www.npmjs.com/package/{name}",
                 latest=latest, modified=_ts(abbrev.get("modified")))


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


_KEY_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")
_KEY_POS = {ch: (r, c) for r, row in enumerate(_KEY_ROWS) for c, ch in enumerate(row)}
# letter groups that read alike in a package listing; the left one is what a squatter types
HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"))
SHORT = 4  # popular names this long are judged only with registry facts (see ShortNameTests)
SHORT_LOOKALIKE_DAYS = 365


def _adjacent(a: str, b: str) -> bool:
    """Neighbouring keys on a US QWERTY keyboard (the same row, or the row above or below)."""
    if a == b or a not in _KEY_POS or b not in _KEY_POS:
        return False
    (r1, c1), (r2, c2) = _KEY_POS[a], _KEY_POS[b]
    return abs(r1 - r2) <= 1 and abs(c1 - c2) <= 1


def typo_kind(key: str, target: str) -> str:
    """How `key` differs from `target`: the kind of slip, for the finding's title and confidence."""
    if len(key) == len(target):
        diff = [i for i, (a, b) in enumerate(zip(key, target)) if a != b]
        if len(diff) == 1:
            return "adjacent-key" if _adjacent(key[diff[0]], target[diff[0]]) else "substitution"
        if len(diff) == 2 and diff[1] == diff[0] + 1 and key[diff[0]] == target[diff[1]] \
                and key[diff[1]] == target[diff[0]]:
            return "transposition"
    elif len(key) + 1 == len(target) and any(key == target[:i] + target[i + 1:] for i in range(len(target))):
        return "omission"
    elif len(key) == len(target) + 1:
        for i in range(len(key)):
            if key[:i] + key[i + 1:] == target:
                return "repetition" if (i and key[i] == key[i - 1]) or key[i:i + 2] == key[i] * 2 else "insertion"
    return "two edits"


@dataclass(frozen=True)
class Lookalike:
    target: str   # the popular package's display name
    kind: str     # separator, homoglyph, transposition, adjacent-key, omission, repetition, insertion, ...
    short: bool   # the target is a 4-letter name: judged only with registry facts


_CONFIDENCE = {"homoglyph": 75, "separator": 70, "transposition": 65, "adjacent-key": 65, "omission": 65,
               "repetition": 65, "insertion": 55, "substitution": 55, "two edits": 50}
_PHRASE = {"homoglyph": "spelled with lookalike letters like", "separator": "the same name, with other separators, as",
           "transposition": "two swapped letters from", "adjacent-key": "one adjacent-key slip from",
           "omission": "one missing letter from", "repetition": "one doubled letter from",
           "insertion": "one extra letter from", "substitution": "one changed letter from",
           "two edits": "two edits from"}


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


def _flat(key: str) -> str:
    return key.replace("-", "").replace("_", "").replace(".", "")


def lookalike(name: str, eco: str) -> Lookalike | None:
    """The popular package this name imitates and how, or None."""
    popular, legit = _popular()
    targets = popular.get(eco, {})
    key = _key(name, eco)
    if key in targets or key in legit.get(eco, set()) or len(key) < SHORT:
        return None
    if len(key) == SHORT:
        for tkey, display in targets.items():
            if len(tkey) == SHORT and (kind := typo_kind(key, tkey)) in ("adjacent-key", "transposition"):
                return Lookalike(display, kind, True)
        return None
    flat = _flat(key)
    for tkey, display in targets.items():
        if len(tkey) <= SHORT:
            continue
        if flat == _flat(tkey):
            return Lookalike(display, "separator", False)  # open-ai / openai, py-yaml / pyyaml
        limit = 2 if len(tkey) >= 10 else 1
        if _damerau(key, tkey, limit) <= limit:
            return Lookalike(display, typo_kind(key, tkey), False)
    for seen, meant in HOMOGLYPHS:  # nurnpy / numpy: two edits, so no distance limit above catches it
        if seen in key and (display := targets.get(key.replace(seen, meant))) and len(key.replace(seen, meant)) > SHORT:
            return Lookalike(display, "homoglyph", False)
    return None


def looks_like(name: str, eco: str) -> str | None:
    """The popular package this name imitates, or None (short names included)."""
    hit = lookalike(name, eco)
    return hit.target if hit else None


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
    return out + release_findings(comp, facts, now)


def typosquat_findings(comp: Component, hit: Lookalike | None = None, facts: Facts | None = None,
                       now: dt.datetime | None = None) -> list[Finding]:
    """A lookalike name. A short-name lookalike needs `facts` showing a package under a year old."""
    hit = hit or lookalike(comp.name, comp.ecosystem or "")
    if hit is None:
        return []
    fix = (f"If you meant {hit.target}, fix the name. Lookalike names are a common way to slip malware into "
           "dependencies.")
    detail: dict[str, Any] = {"looks_like": hit.target, "typo": hit.kind}
    if not hit.short:
        return [_finding("ait.pkg.typosquat", "medium", "suspicious", _CONFIDENCE.get(hit.kind, 55), comp,
                         f"{comp.name} is {_PHRASE[hit.kind]} the widely used package {hit.target}; check that this "
                         "is the package you meant", fix, "ait-rules", None, detail)]
    if facts is None or facts.created is None or now is None:
        return []
    days = _hours(now, facts.created) // 24
    if days >= SHORT_LOOKALIKE_DAYS:
        return []
    eco = comp.ecosystem or ""
    return [_finding("ait.pkg.typosquat", "medium", "suspicious", 60, comp,
                     f"{comp.name} is {_PHRASE[hit.kind]} the widely used package {hit.target}, and was first "
                     f"published {days} days ago; check that this is the package you meant", fix,
                     "pypi" if eco == "pypi" else "npm-registry", facts.url,
                     {**detail, "first_published": facts.created.isoformat(), "age_days": days})]


RECENT_RELEASE_DAYS = 30   # release signals judge only a release this recent: older ones have had scrutiny
DORMANT_DAYS = 730         # no release for two years, then one
VERSION_JUMP = 10          # majors above every earlier release (1.x → 99.0.0); CalVer years are not jumps
CALVER_YEARS = range(2000, 2101)


def _major(version: str) -> int | None:
    digits = ""
    for ch in version.lstrip("vV"):
        if not ch.isdigit():
            break
        digits += ch
    return int(digits) if digits else None


def _release_in_use(comp: Component, facts: Facts, now: dt.datetime) -> str | None:
    """The release an install fetches (the pinned one, else the newest) if it came out in the last 30 days.

    Needs publish times: every PyPI package, and npm packages whose full document is read. For other npm
    packages the `latest` tag stands in, counted as recent when the package document changed in the last
    30 days (npm's abbreviated document has no per-version times)."""
    eco = comp.ecosystem or ""
    times = facts.version_times
    if times:
        if comp.version:
            version = next((v for v in times if versions_equal(eco, comp.version, v)), None)
        else:
            version = max(times, key=times.__getitem__)
        when = times.get(version) if version else None
    else:
        version = facts.latest
        if version and comp.version and not versions_equal(eco, comp.version, version):
            version = None
        when = facts.modified
    if version is None or when is None or _hours(now, when) // 24 > RECENT_RELEASE_DAYS:
        return None
    return version


def release_findings(comp: Component, facts: Facts, now: dt.datetime) -> list[Finding]:
    """A recent release after years of silence, or one whose major version jumps far ahead."""
    times = facts.version_times
    eco = comp.ecosystem or ""
    version = _release_in_use(comp, facts, now)
    if version is None or version not in times:
        return []
    when = times[version]
    age = _hours(now, when) // 24
    earlier = {v: t for v, t in times.items() if t < when}
    if not earlier:
        return []
    reg = REGISTRY_NAMES.get(eco, eco)
    src = "pypi" if eco == "pypi" else "npm-registry"
    out: list[Finding] = []
    previous = max(earlier, key=earlier.__getitem__)
    quiet = (when - earlier[previous]).days
    if quiet >= DORMANT_DAYS:
        out.append(_finding(
            "ait.pkg.dormant-release", "medium", "suspicious", 50, comp,
            f"{comp.name} {version} was published {age} days ago, the first release in {quiet / 365.25:.1f} years; "
            "a long-quiet package that suddenly releases can mean a taken-over account",
            f"Stay on {previous} until you have checked who published {version} and what it changed.",
            src, facts.url, {"registry": reg, "version": version, "published": when.isoformat(),
                             "previous": previous, "quiet_days": quiet}))
    new = _major(version)
    majors = [m for v in earlier if (m := _major(v)) is not None]
    if new is not None and majors and new - max(majors) >= VERSION_JUMP and new not in CALVER_YEARS:
        out.append(_finding(
            "ait.pkg.version-jump", "medium", "suspicious", 50, comp,
            f"{comp.name} {version} jumps from major version {max(majors)} to {new} ({age} days ago); "
            "dependency-confusion attacks publish inflated version numbers so that installers prefer them",
            f"Check that {version} comes from the package's own maintainers. If you use a private package of "
            "this name, install it from your private index with the index pinned (pip --index-url, an .npmrc scope).",
            src, facts.url, {"registry": reg, "version": version, "published": when.isoformat(),
                             "previous_major": max(majors), "major": new}))
    return out


def _stable_key(eco: str, version: str) -> tuple | None:
    """A sort key for a final release; None for a pre-release or a version that does not parse."""
    if eco == "pypi":
        key = pep440_parse(version)
        return key if key and key[2] == (10**9,) and key[4] == (10**9,) else None
    key = semver_parse(version)
    return key if key and key[3] == (1,) else None


def _previous(eco: str, version: str, versions: list[str]) -> str | None:
    """The greatest final release below `version`: version order, not time, so a backport on an older
    line is compared with that line, not with the newest release."""
    parse = pep440_parse if eco == "pypi" else semver_parse
    mine = parse(version)
    if mine is None:
        return None
    below = [(k, v) for v in versions if (k := _stable_key(eco, v)) is not None and k < mine]
    return max(below)[1] if below else None


def _pypi_publisher(doc: dict | None) -> str | None:
    """The repository (or account) of a PEP 740 trusted publisher, from a provenance document."""
    bundles = doc.get("attestation_bundles") if isinstance(doc, dict) else None
    for bundle in bundles if isinstance(bundles, list) else []:
        pub = bundle.get("publisher") if isinstance(bundle, dict) else None
        if isinstance(pub, dict):
            who = pub.get("repository") or pub.get("email")
            if isinstance(who, str) and who:
                return f"{pub.get('kind', '')}:{who}" if pub.get("kind") not in (None, "GitHub") else who
    return None


def _npm_user(manifest: dict) -> tuple[str | None, bool]:
    """Who published an npm version, and whether it came through trusted publishing."""
    user = manifest.get("_npmUser") if isinstance(manifest.get("_npmUser"), dict) else {}
    name = user.get("name") if isinstance(user.get("name"), str) else None
    return name, bool(user.get("trustedPublisher"))


def _npm_signed(manifest: dict) -> bool:
    dist = manifest.get("dist") if isinstance(manifest.get("dist"), dict) else {}
    return _npm_user(manifest)[1] or bool(dist.get("attestations"))


def publisher_findings(comp: Component, facts: Facts, client: RegistryClient, now: dt.datetime) -> list[Finding]:
    """Who published the release in use, compared with the release before it (design doc 13 C17).

    `ait.pkg.provenance-dropped`: the previous release was signed (a PEP 740 attestation on PyPI; trusted
    publishing or `--provenance` on npm) and this one is not — the second ultralytics wave was uploaded
    with a stolen token, outside the project's trusted publisher. `ait.pkg.publisher-change`: on npm, the
    publisher was neither a maintainer of the previous release nor its publisher (event-stream); on PyPI,
    both releases are attested but from different repositories. Fetches one or two small documents, and
    only for a release from the last 30 days."""
    version = _release_in_use(comp, facts, now)
    eco = comp.ecosystem or ""
    previous = _previous(eco, version, facts.versions or list(facts.version_times)) if version else None
    if version is None or previous is None:
        return []
    reg = REGISTRY_NAMES.get(eco, eco)
    base = {"registry": reg, "version": version, "previous": previous}
    hold = f"Stay on {previous} until you have checked who published {version}."
    if eco == "pypi":
        cur_url, prev_url = facts.attested.get(version), facts.attested.get(previous)
        if prev_url and not cur_url:
            return [_finding(
                "ait.pkg.provenance-dropped", "medium", "suspicious", 60, comp,
                f"{comp.name} {version} has no attestation, though {previous} was published with one; it may "
                "have been uploaded outside the project's trusted publisher (a stolen token)",
                hold + " A release that skips the project's usual publishing workflow can come from a stolen "
                "upload token.", "pypi", facts.url, base)]
        if not (cur_url and prev_url):
            return []
        who, before = _pypi_publisher(client.pypi_provenance(cur_url)), _pypi_publisher(client.pypi_provenance(prev_url))
        if who and before and who.lower() != before.lower():
            return [_finding(
                "ait.pkg.publisher-change", "medium", "suspicious", 50, comp,
                f"{comp.name} {version} was published from {who}, but {previous} from {before}; check that the "
                "project really moved", hold, "pypi", facts.url,
                {**base, "publisher": who, "previous_publisher": before})]
        return []
    cur, prev = client.npm_version(comp.name, version), client.npm_version(comp.name, previous)
    if not isinstance(cur, dict) or not isinstance(prev, dict):
        return []
    who, trusted = _npm_user(cur)
    before, _ = _npm_user(prev)
    if _npm_signed(prev) and not _npm_signed(cur):
        return [_finding(
            "ait.pkg.provenance-dropped", "medium", "suspicious", 60, comp,
            f"{comp.name} {version} was published by {who or 'an unknown account'} without the provenance "
            f"{previous} had; it may have been uploaded outside the project's CI (a stolen token)",
            hold + " A release that skips the project's usual publishing workflow can come from a stolen "
            "token.", "npm-registry", facts.url, {**base, "publisher": who, "previous_publisher": before})]
    maintainers = prev.get("maintainers") if isinstance(prev.get("maintainers"), list) else []
    known = {m.get("name") for m in maintainers if isinstance(m, dict)} | {before}
    if who and not trusted and who not in known:
        return [_finding(
            "ait.pkg.publisher-change", "medium", "suspicious", 50, comp,
            f"{comp.name} {version} was published by {who}, who was not a maintainer of {previous}; a new "
            "publisher can mean a taken-over or handed-over package", hold, "npm-registry", facts.url,
            {**base, "publisher": who, "previous_publisher": before,
             "previous_maintainers": sorted(n for n in known if n)})]
    return []


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
    short: dict[int, Lookalike] = {}  # id(component) -> a short-name lookalike, judged with registry facts
    for comp in libs:
        hit = lookalike(comp.name, comp.ecosystem or "")
        if hit is not None and hit.short:
            short[id(comp)] = hit
        elif hit is not None:
            findings += typosquat_findings(comp, hit)
    examined = result.examine(sources.REGISTRY.name)
    if client.offline:
        examined.skipped = "offline"
        if short:
            pairs = [f"{c.name} / {short[id(c)].target}" for c in libs if id(c) in short]
            result.notes.append(
                f"registry: {len(pairs)} package name(s) one keystroke from a popular 4-letter name were not judged "
                f"({', '.join(pairs[:3])}{' …' if len(pairs) > 3 else ''}); only the registry can tell an "
                "established package from a new squat")
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
            facts = _lookup(client, comps[0])
        except net.NetError as err:
            return key, comps, None, err, [], []
        published: list[Finding] = []
        unchecked: list[str] = []
        for comp in comps if facts is not None else []:
            try:
                published += publisher_findings(comp, facts, client, now)
            except net.NetError as err:
                unchecked.append(f"{comp.name} ({err})")
        return key, comps, facts, None, published, unchecked

    errors: list[str] = []
    unverified: list[str] = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for key, comps, facts, err, published, unchecked in pool.map(one, sorted(seen.items())):
            if err is not None:
                examined.errors += 1
                errors.append(f"{key[1]} ({err})")
                continue
            examined.checked += 1
            examined.with_data += 1
            for comp in comps:
                findings += facts_findings(comp, facts, now)
                if id(comp) in short and facts is not None:
                    findings += typosquat_findings(comp, short[id(comp)], facts, now)
            findings += published
            unverified += unchecked
    if errors:
        result.notes.append(f"registry: {len(errors)} lookup(s) failed — existence and age UNVERIFIED, not safe: "
                            + "; ".join(errors[:3]) + (" …" if len(errors) > 3 else ""))
    if unverified:
        result.notes.append(f"registry: who published {len(unverified)} recent release(s) is UNVERIFIED (lookup "
                            "failed): " + "; ".join(unverified[:3]) + (" …" if len(unverified) > 3 else ""))
    return findings
