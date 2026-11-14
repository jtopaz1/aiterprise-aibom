"""Tolerant text and JSON reading.

Two measured vendors failed on PowerShell-written JSON (UTF-16 with a BOM — design doc 13, G6),
so every parser reads through these helpers: UTF-8 (with or without BOM) and UTF-16 LE/BE BOMs.
"""

from __future__ import annotations

import codecs
import json
from pathlib import Path
from typing import Any

DEFAULT_MAX_BYTES = 16 * 1024 * 1024  # manifests/configs larger than this are not text we parse


class TooLarge(Exception):
    pass


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


def read_text(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
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
