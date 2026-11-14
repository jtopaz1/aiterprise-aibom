"""A small, safe YAML subset parser (the engine has zero runtime dependencies).

Supported: block mappings and sequences, flow `[...]` / `{...}` collections, single/double quoted
scalars, `|` / `>` block scalars, comments, a leading `---`. Not supported (by design): tags,
anchors/aliases, complex `?` keys, multiple documents (only the first is read). Nothing is ever
constructed from tags, so hostile input cannot execute code.

Scalars: `null`/`~`/empty → None, `true`/`false` → bool, plain integers → int when `typed=True`.
Anything with a dot stays a string, so versions like `1.10` are never turned into floats.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["load", "YAMLError"]


class YAMLError(ValueError):
    pass


_INT = re.compile(r"^[-+]?(0|[1-9][0-9]*)$")
_BLOCK_INDICATOR = re.compile(r"^[|>][-+]?[1-9]?$|^[|>][1-9][-+]?$")


def load(text: str, *, typed: bool = True) -> Any:
    return _Parser(text.lstrip("﻿"), typed).parse()


def _strip_comment(line: str) -> str:
    in_single = in_double = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_double:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                if i + 1 < n and line[i + 1] == "'":
                    i += 2
                    continue
                in_single = False
        else:
            if ch == "#" and (i == 0 or line[i - 1] in " \t"):
                return line[:i].rstrip()
            if ch == '"' and (i == 0 or line[i - 1] in " \t:-[{,"):
                in_double = True
            elif ch == "'" and (i == 0 or line[i - 1] in " \t:-[{,"):
                in_single = True
        i += 1
    return line.rstrip()


def _is_seq_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _unescape_double(s: str) -> str:
    out: list[str] = []
    i = 0
    n = len(s)
    simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", '"': '"', "\\": "\\", "/": "/", " ": " "}
    while i < n:
        ch = s[i]
        if ch == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < n + 1:
                out.append(chr(int(s[i + 2 : i + 4], 16)))
                i += 4
                continue
            if nxt == "u":
                out.append(chr(int(s[i + 2 : i + 6], 16)))
                i += 6
                continue
            if nxt == "U":
                out.append(chr(int(s[i + 2 : i + 10], 16)))
                i += 10
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


class _Parser:
    def __init__(self, text: str, typed: bool) -> None:
        self.typed = typed
        self.raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.lines: list[tuple[int, int, str]] = []  # (raw index, indent, content)
        seen_content = False
        for idx, raw in enumerate(self.raw):
            stripped = raw.strip()
            if stripped in ("---", "...") or stripped.startswith("--- "):
                if seen_content:
                    break  # second document: ignored
                rest = stripped[4:].strip() if stripped.startswith("--- ") else ""
                if rest:
                    self.lines.append((idx, 0, rest))
                    seen_content = True
                continue
            if raw.startswith("%"):
                continue  # directive
            content = _strip_comment(raw)
            if not content.strip():
                continue
            lead = content[: len(content) - len(content.lstrip())]
            if "\t" in lead:
                raise YAMLError(f"line {idx + 1}: tabs are not allowed for indentation")
            indent = len(lead)
            self.lines.append((idx, indent, content.strip()))
            seen_content = True
        self.pos = 0

    # -- entry -------------------------------------------------------------------------------
    def parse(self) -> Any:
        if not self.lines:
            return None
        first_raw, indent, content = self.lines[0]
        if len(self.lines) == 1 and not _is_seq_item(content) and self._split_key(content) is None:
            self.pos = 1
            return self._inline(content, first_raw)
        value = self._block(indent)
        if self.pos < len(self.lines):
            raw_idx = self.lines[self.pos][0]
            raise YAMLError(f"line {raw_idx + 1}: unexpected content")
        return value

    # -- blocks ------------------------------------------------------------------------------
    def _block(self, indent: int) -> Any:
        _, _, content = self.lines[self.pos]
        if _is_seq_item(content):
            return self._seq(indent)
        return self._map(indent)

    def _seq(self, indent: int) -> list[Any]:
        items: list[Any] = []
        while self.pos < len(self.lines):
            raw_idx, ind, content = self.lines[self.pos]
            if ind < indent or not _is_seq_item(content):
                break
            if ind > indent:
                raise YAMLError(f"line {raw_idx + 1}: unexpected indentation")
            after_dash = content[1:]
            rest = after_dash.strip()
            self.pos += 1
            if not rest:
                if self.pos < len(self.lines) and self.lines[self.pos][1] > indent:
                    items.append(self._block(self.lines[self.pos][1]))
                else:
                    items.append(None)
                continue
            col = ind + 1 + (len(after_dash) - len(after_dash.lstrip(" ")))
            if _is_seq_item(rest) or self._split_key(rest) is not None:
                self.lines.insert(self.pos, (raw_idx, col, rest))
                items.append(self._block(col))
            elif _BLOCK_INDICATOR.match(rest):
                items.append(self._block_scalar(raw_idx, indent, rest))
            else:
                items.append(self._inline(rest, raw_idx))
        return items

    def _map(self, indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while self.pos < len(self.lines):
            raw_idx, ind, content = self.lines[self.pos]
            if ind < indent:
                break
            if ind > indent:
                raise YAMLError(f"line {raw_idx + 1}: unexpected indentation")
            if _is_seq_item(content):
                break
            split = self._split_key(content)
            if split is None:
                raise YAMLError(f"line {raw_idx + 1}: expected 'key: value'")
            key, value_text = split
            self.pos += 1
            if value_text == "":
                value: Any = None
                if self.pos < len(self.lines):
                    _, nind, ncontent = self.lines[self.pos]
                    if nind > indent:
                        value = self._block(nind)
                    elif nind == indent and _is_seq_item(ncontent):
                        value = self._seq(indent)
            elif _BLOCK_INDICATOR.match(value_text):
                value = self._block_scalar(raw_idx, indent, value_text)
            else:
                value = self._inline(value_text, raw_idx)
            result[key] = value
        return result

    # -- keys and scalars -------------------------------------------------------------------
    def _split_key(self, content: str) -> tuple[str, str] | None:
        if content.startswith(("[", "{")):
            return None
        if content[0] in "\"'":
            quote = content[0]
            i = 1
            n = len(content)
            while i < n:
                if content[i] == "\\" and quote == '"':
                    i += 2
                    continue
                if content[i] == quote:
                    if quote == "'" and i + 1 < n and content[i + 1] == "'":
                        i += 2
                        continue
                    break
                i += 1
            if i >= n:
                return None
            rest = content[i + 1 :]
            if rest == ":" or rest.startswith(": "):
                key = self._quoted(content[: i + 1])
                return str(key), rest[1:].strip()
            return None
        depth = 0
        for i, ch in enumerate(content):
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == ":" and depth <= 0:
                if i + 1 == len(content) or content[i + 1] == " ":
                    key = content[:i].strip()
                    if not key:
                        return None
                    return key, content[i + 1 :].strip()
        return None

    def _quoted(self, s: str) -> str:
        if s.startswith('"'):
            return _unescape_double(s[1:-1])
        return s[1:-1].replace("''", "'")

    def _scalar(self, s: str) -> Any:
        s = s.strip()
        if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
            return self._quoted(s)
        if s in ("", "~", "null", "Null", "NULL"):
            return None
        if s in ("true", "True", "TRUE"):
            return True
        if s in ("false", "False", "FALSE"):
            return False
        if self.typed and _INT.match(s):
            return int(s)
        return s

    def _inline(self, text: str, raw_idx: int) -> Any:
        if text.startswith(("[", "{")):
            joined = text
            while not self._balanced(joined) and self.pos < len(self.lines):
                joined += " " + self.lines[self.pos][2]
                self.pos += 1
            value, end = self._flow(joined, 0)
            if joined[end:].strip():
                raise YAMLError(f"line {raw_idx + 1}: trailing characters after flow collection")
            return value
        if text[0] in "\"'" and not (len(text) >= 2 and text[-1] == text[0]):
            # multi-line quoted scalar: fold following lines
            joined = text
            while self.pos < len(self.lines) and not (len(joined) >= 2 and joined[-1] == text[0]):
                joined += " " + self.lines[self.pos][2]
                self.pos += 1
            return self._scalar(joined)
        return self._scalar(text)

    @staticmethod
    def _balanced(s: str) -> bool:
        depth = 0
        quote = ""
        i = 0
        while i < len(s):
            ch = s[i]
            if quote:
                if ch == "\\" and quote == '"':
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in "\"'":
                quote = ch
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            i += 1
        return depth <= 0

    def _flow(self, s: str, i: int) -> tuple[Any, int]:
        n = len(s)
        while i < n and s[i] == " ":
            i += 1
        if i >= n:
            return None, i
        ch = s[i]
        if ch == "[":
            items: list[Any] = []
            i += 1
            while True:
                while i < n and s[i] in " ,":
                    if s[i] == ",":
                        pass
                    i += 1
                if i >= n:
                    raise YAMLError("unterminated flow sequence")
                if s[i] == "]":
                    return items, i + 1
                value, i = self._flow(s, i)
                items.append(value)
                while i < n and s[i] == " ":
                    i += 1
                if i < n and s[i] == ",":
                    i += 1
        if ch == "{":
            mapping: dict[str, Any] = {}
            i += 1
            while True:
                while i < n and s[i] in " ,":
                    i += 1
                if i >= n:
                    raise YAMLError("unterminated flow mapping")
                if s[i] == "}":
                    return mapping, i + 1
                key, i = self._flow_scalar(s, i, key_mode=True)
                while i < n and s[i] == " ":
                    i += 1
                value: Any = None
                if i < n and s[i] == ":":
                    value, i = self._flow(s, i + 1)
                mapping[str(key)] = value
                while i < n and s[i] == " ":
                    i += 1
                if i < n and s[i] == ",":
                    i += 1
        return self._flow_scalar(s, i, key_mode=False)

    def _flow_scalar(self, s: str, i: int, key_mode: bool) -> tuple[Any, int]:
        n = len(s)
        if s[i] in "\"'":
            quote = s[i]
            j = i + 1
            while j < n:
                if s[j] == "\\" and quote == '"':
                    j += 2
                    continue
                if s[j] == quote:
                    if quote == "'" and j + 1 < n and s[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            return self._quoted(s[i : j + 1]), j + 1
        j = i
        while j < n:
            c = s[j]
            if c in ",]}":
                break
            if c == ":" and (j + 1 == n or s[j + 1] in " ,]}"):
                if key_mode:
                    break
            j += 1
        token = s[i:j].strip()
        return (token if key_mode else self._scalar(token)), j

    def _block_scalar(self, raw_idx: int, parent_indent: int, indicator: str) -> str:
        style = indicator[0]
        chomp = "-" if "-" in indicator else ("+" if "+" in indicator else "")
        explicit = next((int(c) for c in indicator if c.isdigit()), None)
        body: list[str] = []
        block_indent = parent_indent + explicit if explicit else None
        last = raw_idx
        j = raw_idx + 1
        while j < len(self.raw):
            line = self.raw[j]
            if not line.strip():
                body.append("")
                j += 1
                continue
            ind = len(line) - len(line.lstrip(" "))
            if ind <= parent_indent:
                break
            if block_indent is None:
                block_indent = ind
            if ind < block_indent:
                break
            body.append(line[block_indent:])
            last = j
            j += 1
        # drop trailing blank lines beyond the last content line for clip/strip
        while body and body[-1] == "" and chomp != "+":
            body.pop()
        while self.pos < len(self.lines) and self.lines[self.pos][0] <= last:
            self.pos += 1
        if style == "|":
            text = "\n".join(body)
        else:
            parts: list[str] = []
            for line in body:
                if line == "":
                    parts.append("\n")
                elif parts and not parts[-1].endswith("\n"):
                    parts.append(" " + line)
                else:
                    parts.append(line)
            text = "".join(parts)
        if chomp == "-":
            return text
        return text + "\n" if text else text
