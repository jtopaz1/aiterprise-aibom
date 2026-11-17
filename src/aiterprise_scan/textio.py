"""Tolerant text and JSON reading.

Two measured vendors failed on PowerShell-written JSON (UTF-16 with a BOM — design doc 13, G6),
so every parser reads through these helpers: UTF-8 (with or without BOM) and UTF-16 LE/BE BOMs.
"""

from __future__ import annotations

import codecs
import contextlib
import contextvars
import json
import re
from pathlib import Path
from typing import Any

DEFAULT_MAX_BYTES = 16 * 1024 * 1024  # manifests/configs larger than this are not text we parse

# C0/C1 controls (ESC sequences, BEL, CR, newlines), zero-width and bidi-override characters
_UNPRINTABLE = re.compile("[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤﻿"
                          "\U000e0000-\U000e007f]")


class TooLarge(Exception):
    pass


def printable(text: Any) -> str:
    """Scanned text made safe to show: every control, bidi or invisible character becomes a
    space, so a hostile name or description cannot drive the terminal or forge report lines."""
    return _UNPRINTABLE.sub(" ", str(text))


def decode_bytes(raw: bytes) -> str:
    if raw.startswith(codecs.BOM_UTF8):
        return raw[len(codecs.BOM_UTF8):].decode("utf-8", errors="replace")
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        return raw.decode("utf-16", errors="replace")
    # UTF-16 without BOM: every other byte is NUL in ASCII-range text.
    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0 and raw[0] != 0:
        return raw.decode("utf-16-le", errors="replace")
    if len(raw) >= 4 and raw[0] == 0 and raw[2] == 0 and raw[1] != 0:
        return raw.decode("utf-16-be", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


READ_ONCE_BUDGET = 256 * 1024 * 1024  # characters of text a scan keeps for its other analyzers


class _ReadOnce:
    def __init__(self, budget: int) -> None:
        self.budget = budget
        self.used = 0
        self.sizes: dict[Path, int] = {}
        self.texts: dict[Path, str] = {}


_read_once: contextvars.ContextVar[_ReadOnce | None] = contextvars.ContextVar("textio_read_once", default=None)


@contextlib.contextmanager
def read_once(budget: int = READ_ONCE_BUDGET):
    """Within this block, a file read with `read_text` is read from disk once: several analyzers
    look at the same source file, and opening it again is most of what a large scan costs on some
    machines. Texts are kept until `budget` characters are held; later files are read each time."""
    token = _read_once.set(_ReadOnce(budget))
    try:
        yield
    finally:
        _read_once.reset(token)


def read_text(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    memo = _read_once.get()
    if memo is not None:
        size = memo.sizes.get(path)
        if size is None:
            size = memo.sizes[path] = path.stat().st_size
        if size > max_bytes:
            raise TooLarge(f"{path} is {size} bytes (limit {max_bytes})")
        text = memo.texts.get(path)
        if text is None:
            text = decode_bytes(path.read_bytes())
            if memo.used + len(text) <= memo.budget:
                memo.texts[path] = text
                memo.used += len(text)
        return text
    size = path.stat().st_size
    if size > max_bytes:
        raise TooLarge(f"{path} is {size} bytes (limit {max_bytes})")
    return decode_bytes(path.read_bytes())


def read_json(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    return json.loads(read_text(path, max_bytes))


def loads_json(text: str) -> Any:
    return json.loads(text.lstrip("﻿"))


def line_of(text: str, needle: str, start: int = 0) -> int | None:
    """1-based line number of the first occurrence of `needle`, or None."""
    idx = text.find(needle, start)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def strip_json_comments(text: str) -> str:
    """Remove // and /* */ comments and trailing commas (VS Code / Cursor configs are JSONC)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(ch)
            i += 1
    cleaned = "".join(out)
    # trailing commas before } or ]
    result: list[str] = []
    in_str = False
    i, n = 0, len(cleaned)
    while i < n:
        ch = cleaned[i]
        if in_str:
            result.append(ch)
            if ch == "\\" and i + 1 < n:
                result.append(cleaned[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            result.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and cleaned[j] in " \t\r\n":
                j += 1
            if j < n and cleaned[j] in "}]":
                i += 1
                continue
            result.append(ch)
        else:
            result.append(ch)
        i += 1
    return "".join(result)


def loads_jsonc(text: str) -> Any:
    return json.loads(strip_json_comments(text.lstrip("﻿")))


# --------------------------------------------------------------------------------------------
# JSON5 (OpenClaw's config): comments, trailing commas, unquoted keys, single quotes, hex numbers
# --------------------------------------------------------------------------------------------

_JSON5_MAX_DEPTH = 64
_JSON5_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_JSON5_NUMBER = re.compile(r"[+-]?(?:0[xX][0-9A-Fa-f]+|Infinity|NaN|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)")
_JSON5_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def loads_json5(text: str) -> Any:
    """Parse JSON5. Anything else, a nesting deeper than 64 included, raises ValueError."""
    parser = _Json5(text.lstrip("﻿"))
    value = parser.value(0)
    parser.space()
    if parser.i != len(parser.s):
        raise ValueError(f"JSON5: unexpected text at offset {parser.i}")
    return value


class _Json5:
    def __init__(self, s: str) -> None:
        self.s, self.i = s, 0

    def fail(self, what: str) -> ValueError:
        return ValueError(f"JSON5: {what} at offset {self.i}")

    def space(self) -> None:
        s, n = self.s, len(self.s)
        while self.i < n:
            if s[self.i] in " \t\r\n\f\v\u00a0\ufeff\u2028\u2029":
                self.i += 1
            elif s.startswith("//", self.i):
                j = s.find("\n", self.i)
                self.i = n if j < 0 else j
            elif s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                if j < 0:
                    raise self.fail("unterminated comment")
                self.i = j + 2
            else:
                return

    def value(self, depth: int) -> Any:
        if depth > _JSON5_MAX_DEPTH:
            raise self.fail("nesting too deep")
        self.space()
        if self.i >= len(self.s):
            raise self.fail("missing value")
        c = self.s[self.i]
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c in "\"'":
            return self.string()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(word, self.i) and not _JSON5_IDENT.match(self.s, self.i + len(word)):
                self.i += len(word)
                return val
        m = _JSON5_NUMBER.match(self.s, self.i)
        if not m or _JSON5_IDENT.match(self.s, m.end()):
            raise self.fail("not a value")
        self.i = m.end()
        tok = m.group(0)
        body = tok.lstrip("+-")
        sign = -1 if tok.startswith("-") else 1
        if body[:2].lower() == "0x":
            return sign * int(body, 16)
        if body in ("Infinity", "NaN") or any(ch in body for ch in ".eE"):
            return float(tok)
        return int(tok)

    def obj(self, depth: int) -> dict:
        self.i += 1
        out: dict[str, Any] = {}
        self.space()
        if self.s[self.i:self.i + 1] == "}":
            self.i += 1
            return out
        while True:
            self.space()
            if self.s[self.i:self.i + 1] in ("\"", "'"):
                key = self.string()
            else:
                m = _JSON5_IDENT.match(self.s, self.i)
                if not m:
                    raise self.fail("not a key")
                key, self.i = m.group(0), m.end()
            self.space()
            if self.s[self.i:self.i + 1] != ":":
                raise self.fail("missing ':'")
            self.i += 1
            out[key] = self.value(depth + 1)
            if self.end_of_item("}"):
                return out

    def arr(self, depth: int) -> list:
        self.i += 1
        out: list[Any] = []
        self.space()
        if self.s[self.i:self.i + 1] == "]":
            self.i += 1
            return out
        while True:
            out.append(self.value(depth + 1))
            if self.end_of_item("]"):
                return out

    def end_of_item(self, close: str) -> bool:
        """After an item: True at the closing bracket (a trailing comma allowed), False after a comma."""
        self.space()
        c = self.s[self.i:self.i + 1]
        if c == close:
            self.i += 1
            return True
        if c != ",":
            raise self.fail(f"missing ',' or '{close}'")
        self.i += 1
        self.space()
        if self.s[self.i:self.i + 1] == close:
            self.i += 1
            return True
        return False

    def string(self) -> str:
        quote, s, n = self.s[self.i], self.s, len(self.s)
        self.i += 1
        out: list[str] = []
        while True:
            if self.i >= n:
                raise self.fail("unterminated string")
            c = s[self.i]
            if c == quote:
                self.i += 1
                return "".join(out)
            if c in "\r\n":
                raise self.fail("newline in a string")
            if c != "\\":
                out.append(c)
                self.i += 1
                continue
            e = s[self.i + 1:self.i + 2]
            self.i += 2
            if e in _JSON5_ESCAPES:
                out.append(_JSON5_ESCAPES[e])
            elif e in ("u", "x"):
                width = 4 if e == "u" else 2
                digits = s[self.i:self.i + width]
                if len(digits) != width or not all(ch in "0123456789abcdefABCDEF" for ch in digits):
                    raise self.fail("bad escape")
                out.append(chr(int(digits, 16)))
                self.i += width
            elif e == "\r":
                if s[self.i:self.i + 1] == "\n":
                    self.i += 1  # a line continuation adds nothing
            elif e in ("\n", "\u2028", "\u2029"):
                pass
            elif e:
                out.append(e)  # \\ \' \" \/ and any other character stand for themselves
            else:
                raise self.fail("unterminated string")
