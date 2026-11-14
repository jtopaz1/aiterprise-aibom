"""Version parsing and range membership for PyPI (PEP 440) and npm (semver).

Used to answer one question honestly: *can this declared range resolve to a known-bad
version?* Every function returns None when it cannot decide, and callers must treat None as
"not evaluated", never as "safe".
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------------------------
# PEP 440
# --------------------------------------------------------------------------------------------

_PEP440 = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?:(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_NEG = (-1,)
_POS = (10**9,)


def pep440_parse(version: str) -> tuple | None:
    m = _PEP440.match(version or "")
    if not m:
        return None
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    epoch = int(m.group("epoch") or 0)
    pre_l = m.group("pre_l")
    post_present = m.group("post_n1") is not None or m.group("post_l") is not None
    dev_present = m.group("dev_l") is not None
    if pre_l:
        pre = (_PRE_RANK[pre_l.lower()], int(m.group("pre_n") or 0))
    elif dev_present and not post_present:
        pre = _NEG
    else:
        pre = _POS
    if post_present:
        post = (int(m.group("post_n1") or m.group("post_n2") or 0),)
    else:
        post = _NEG
    dev = (int(m.group("dev_n") or 0),) if dev_present else _POS
    return (epoch, tuple(release), pre, post, dev)


def pep440_normalize(version: str) -> str:
    """Comparable canonical string (for exact matching of e.g. `1.82.07` vs `1.82.7`)."""
    key = pep440_parse(version)
    return repr(key) if key else (version or "").strip().lower()


def _release_of(version: str) -> list[int] | None:
    m = _PEP440.match(version or "")
    if not m:
        return None
    return [int(x) for x in m.group("release").split(".")]


def _pep440_clause(clause: str, candidate: tuple, candidate_raw: str) -> bool | None:
    clause = clause.strip()
    if not clause:
        return True
    m = re.match(r"^(===|==|!=|~=|>=|<=|>|<)\s*(.+)$", clause)
    if not m:
        # a bare version is treated as ==
        if pep440_parse(clause):
            m = re.match(r"^()(.+)$", clause)
            op, target = "==", clause
        else:
            return None
    else:
        op, target = m.group(1), m.group(2).strip()
    if op == "===":
        return candidate_raw.strip().lower() == target.lower()
    if op in ("==", "!=") and target.endswith(".*"):
        prefix = _release_of(target[:-2])
        rel = _release_of(candidate_raw)
        if prefix is None or rel is None:
            return None
        rel = rel + [0] * max(0, len(prefix) - len(rel))
        hit = rel[: len(prefix)] == prefix
        return hit if op == "==" else not hit
    tkey = pep440_parse(target)
    if tkey is None:
        return None
    if op == "==":
        return candidate[:2] == tkey[:2] and candidate[2:] == tkey[2:]
    if op == "!=":
        return candidate != tkey
    if op == ">=":
        return candidate >= tkey
    if op == "<=":
        return candidate <= tkey
    if op == ">":
        return candidate > tkey
    if op == "<":
        return candidate < tkey
    if op == "~=":
        rel = _release_of(target)
        if rel is None or len(rel) < 2:
            return None
        upper = rel[:-1]
        upper[-1] += 1
        ukey = pep440_parse(".".join(str(x) for x in upper))
        return candidate >= tkey and ukey is not None and candidate < ukey
    return None


def pypi_spec_contains(spec: str, version: str) -> bool | None:
    """Does PEP 440 specifier set `spec` (e.g. `>=1.80,<1.90`) admit `version`?"""
    candidate = pep440_parse(version)
    if candidate is None:
        return None
    spec = (spec or "").strip()
    if not spec or spec == "*":
        return True
    result = True
    for clause in spec.split(","):
        r = _pep440_clause(clause, candidate, version)
        if r is None:
            return None
        result = result and r
    return result


# --------------------------------------------------------------------------------------------
# npm semver
# --------------------------------------------------------------------------------------------

_SEMVER = re.compile(
    r"^\s*[v=]?\s*(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$"
)
_PARTIAL = re.compile(r"^\s*[v=]?\s*(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$")


def _pre_key(pre: str | None) -> tuple:
    if pre is None:
        return (1,)  # a release sorts after its prereleases
    parts: list[tuple] = []
    for p in pre.split("."):
        parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    return (0, tuple(parts))


def semver_parse(version: str) -> tuple | None:
    m = _SEMVER.match(version or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), _pre_key(m.group(4)))


def _v(major: int, minor: int, patch: int, pre: str | None = None) -> tuple:
    return (major, minor, patch, _pre_key(pre))


def _wild(x: str | None) -> bool:
    return x is None or x in ("x", "X", "*")


def _partial_to_comparators(op: str, text: str) -> list[tuple[str, tuple]] | None:
    m = _PARTIAL.match(text)
    if not m:
        return None
    ma, mi, pa, pre = m.group(1), m.group(2), m.group(3), m.group(4)
    if _wild(ma):
        if op in ("", "=", ">=", "<=", "^", "~"):
            return []  # any
        if op in ("<", ">"):
            return [("<", _v(0, 0, 0, "0"))]  # matches nothing
    major = int(ma)
    if _wild(mi):
        lo, hi = _v(major, 0, 0), _v(major + 1, 0, 0, "0")
        exact_known = False
    elif _wild(pa):
        minor = int(mi)
        lo, hi = _v(major, minor, 0), _v(major, minor + 1, 0, "0")
        exact_known = False
    else:
        minor, patch = int(mi), int(pa)
        lo = _v(major, minor, patch, pre)
        hi = None
        exact_known = True
    if op in ("", "="):
        if exact_known:
            return [(">=", lo), ("<=", lo)]
        return [(">=", lo), ("<", hi)]
    if op == ">=":
        return [(">=", lo)]
    if op == ">":
        return [(">", lo)] if exact_known else [(">=", hi)]
    if op == "<":
        return [("<", lo)]
    if op == "<=":
        return [("<=", lo)] if exact_known else [("<", hi)]
    if op == "~":
        if _wild(mi):
            return [(">=", lo), ("<", _v(major + 1, 0, 0, "0"))]
        return [(">=", lo), ("<", _v(major, int(mi) + 1, 0, "0"))]
    if op == "^":
        mi_n = 0 if _wild(mi) else int(mi)
        pa_n = 0 if _wild(pa) else int(pa)
        if major > 0 or _wild(mi):
            upper = _v(major + 1, 0, 0, "0")
        elif mi_n > 0 or _wild(pa):
            upper = _v(0, mi_n + 1, 0, "0")
        else:
            upper = _v(0, 0, pa_n + 1, "0")
        return [(">=", lo), ("<", upper)]
    return None


def _cmp(op: str, a: tuple, b: tuple) -> bool:
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def npm_range_contains(rng: str, version: str) -> bool | None:
    """Does npm range `rng` (e.g. `^1.14.0 || ~0.30.0`) admit `version`?"""
    candidate = semver_parse(version)
    if candidate is None:
        return None
    rng = (rng or "").strip()
    if rng in ("", "*", "x", "X", "latest"):
        return True if rng != "latest" else None
    if any(rng.startswith(p) for p in ("http:", "https:", "git", "file:", "link:", "workspace:", "npm:", "github:")):
        return None
    for alternative in rng.split("||"):
        alternative = alternative.strip()
        comparators: list[tuple[str, tuple]] = []
        hyphen = re.match(r"^(\S+)\s+-\s+(\S+)$", alternative)
        if hyphen:
            lo = _partial_to_comparators(">=", hyphen.group(1))
            hi = _partial_to_comparators("<=", hyphen.group(2))
            if lo is None or hi is None:
                return None
            comparators = lo + hi
        else:
            compact = re.sub(r"(\^|~>?|>=|<=|>|<|=)\s+", r"\1", alternative)
            for token in compact.split():
                m = re.match(r"^(\^|~>?|>=|<=|>|<|=)?(.+)$", token)
                if not m:
                    return None
                op, text = m.group(1), m.group(2)
                op = "~" if op and op.startswith("~") else (op or "")
                conv = _partial_to_comparators(op, text)
                if conv is None:
                    return None
                comparators.extend(conv)
        if all(_cmp(op, candidate, bound) for op, bound in comparators):
            return True
    return False


def range_contains(ecosystem: str | None, spec: str, version: str) -> bool | None:
    if ecosystem == "pypi":
        return pypi_spec_contains(spec, version)
    if ecosystem == "npm":
        return npm_range_contains(spec, version)
    return None


def versions_equal(ecosystem: str | None, a: str, b: str) -> bool:
    if ecosystem == "pypi":
        ka, kb = pep440_parse(a), pep440_parse(b)
        if ka is not None and kb is not None:
            return ka == kb
    if ecosystem == "npm":
        ka, kb = semver_parse(a), semver_parse(b)
        if ka is not None and kb is not None:
            return ka == kb
    return a.strip().lower().lstrip("v") == b.strip().lower().lstrip("v")
