"""Reading the arguments of a call in Python or JavaScript source, without executing or parsing it.

Static references (a model id, a store path, an endpoint URL) are plain string literals passed to a
known call. Anything else (a variable, an f-string, an expression) is not a static reference and is
ignored rather than guessed.
"""

from __future__ import annotations

import re

KWARG_RE = re.compile(r"^([A-Za-z_]\w*)\s*=(?!=)\s*(.*)$", re.S)
_LITERAL_RE = re.compile(r"^([rRuU]?)(['\"])(.*)\2$", re.S)
_JS_PROP_RE = re.compile(r"""(?:^|[{,\s])["']?([A-Za-z_$][\w$]*)["']?\s*:\s*(['"`])([^'"`\n\\]*)\2""")


def line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


_COMMENT_STARTS = ("#", "//", "/*", "*", "<!--")


def commented(text: str, offset: int) -> bool:
    """Whether `offset` is on a comment line: a commented-out setting or an example is not in use."""
    line_start = text.rfind("\n", 0, offset) + 1
    return text[line_start:offset].lstrip().startswith(_COMMENT_STARTS)


def _skip_string(text: str, i: int) -> int:
    """`text[i]` is a quote; return the index just past the closing quote."""
    q = text[i]
    triple = text.startswith(q * 3, i)
    if triple:
        end = text.find(q * 3, i + 3)
        return len(text) if end < 0 else end + 3
    j = i + 1
    n = len(text)
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == q or c == "\n":
            return j + 1
        j += 1
    return n


def call_args(text: str, start: int, limit: int = 4000) -> list[tuple[str, int]]:
    """Top-level arguments of a call whose `(` ends just before `start`: [(arg_text, offset)]."""
    args: list[tuple[str, int]] = []
    depth = 0
    i = start
    seg_start = start
    end = min(len(text), start + limit)
    while i < end:
        c = text[i]
        if c in "'\"`":
            i = _skip_string(text, i)
            continue
        if c == "#" and (i == start or text[i - 1] in " \t\n"):
            nl = text.find("\n", i)
            i = end if nl < 0 else nl
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                args.append((text[seg_start:i], seg_start))
                return [(a, o) for a, o in args if a.strip()]
            depth -= 1
        elif c == "," and depth == 0:
            args.append((text[seg_start:i], seg_start))
            seg_start = i + 1
        i += 1
    return []  # unbalanced or too long: not a call we can read safely


def literal(arg: str, offset: int) -> tuple[str, int] | None:
    """(value, absolute offset of the value) when `arg` is a plain string literal."""
    lead = len(arg) - len(arg.lstrip())
    s = arg.strip()
    m = _LITERAL_RE.match(s)
    if not m:
        return None
    body = m.group(3)
    quote = m.group(2)
    if quote in body or "\\" in body or "\n" in body or s.startswith(quote * 3):
        return None
    return body, offset + lead + len(m.group(1)) + 1


def literal_args(text: str, start: int) -> tuple[list[tuple[str, int] | None], dict[str, tuple[str, int]]] | None:
    """The string-literal arguments of a call: (positional, keyword), each value as (text, offset).

    A positional argument that is not a literal is None, so indexes keep their meaning. Keyword
    arguments are Python `name="x"` or the properties of a JavaScript object literal
    `{ name: "x" }` passed as an argument. None when the call cannot be read."""
    args = call_args(text, start)
    if not args and text[start:start + 1] != ")":
        return None
    positional: list[tuple[str, int] | None] = []
    keyword: dict[str, tuple[str, int]] = {}
    for arg, off in args:
        km = KWARG_RE.match(arg.strip())
        if km:
            lead = len(arg) - len(arg.lstrip())
            value = literal(km.group(2), off + lead + km.start(2))
            if value is not None:
                keyword.setdefault(km.group(1), value)
            continue
        stripped = arg.strip()
        if stripped.startswith("{"):
            base = off + (len(arg) - len(arg.lstrip()))
            for pm in _JS_PROP_RE.finditer(stripped):
                keyword.setdefault(pm.group(1), (pm.group(3), base + pm.start(3)))
            continue
        positional.append(literal(arg, off))
    return positional, keyword
