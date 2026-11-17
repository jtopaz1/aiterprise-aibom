"""MCP servers defined in the scanned source (design doc 13 C26).

An agent config names a server; only the server's code says what its tools tell the agent. When the
scanned project builds an MCP server, the tool, prompt and resource descriptions, the parameter
descriptions and the server's instructions are read from its source, without running anything, and
judged with the same poisoning rules as agent configs and bundle manifests (`textrules`). The
server becomes an `mcp-server` component listing its tools, with a `tool_list_hash` over the
descriptions so that a later scan can tell when they changed (C27).

Read statically:
- Python, in a file that imports `mcp` or `fastmcp`: functions decorated with `@<server>.tool`,
  `.prompt` or `.resource` (the `description=` argument, else the docstring; parameter
  descriptions from `Field(description=…)`), `<server>.add_tool(fn, …)`, `Tool(…)` / `Prompt(…)` /
  `Resource(…)` objects with their `inputSchema` property descriptions, and the `instructions=` of
  `FastMCP(…)` / `Server(…)`.
- JavaScript and TypeScript, in a file that imports `@modelcontextprotocol/sdk` or `fastmcp`:
  `<server>.tool(…)`, `.registerTool(…)`, `.prompt(…)`, `.registerPrompt(…)`, `.resource(…)`,
  `.registerResource(…)`, `.addTool({…})` and friends, zod `.describe(…)` parameter descriptions,
  and tool objects (`{name, description, inputSchema}`) such as a low-level server lists.

Only text the code spells out counts: string literals, concatenations of them, and template literals
without substitutions, with escapes decoded (so `\\u200b` is the zero-width space it stands for).
A description built at runtime is not guessed. Tests are not servers.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import scancache, textrules
from .callargs import line_at
from .model import Component, Finding, Location
from .textio import TooLarge, read_text
from .walk import is_test_path, rel_posix

MAX_BYTES = 2 * 1024 * 1024
MAX_TEXT = 64 * 1024  # characters of one description that are kept and judged
MAX_LISTED = 200  # tool, prompt and resource names listed on a component
_PY = {".py", ".pyi"}
_JS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
_PY_SDK_RE = re.compile(r"^[ \t]*(?:from|import)[ \t]+(?:mcp|fastmcp)\b", re.M)
# the SDK (`@modelcontextprotocol/sdk`) or its split packages (`@modelcontextprotocol/server`, …)
_JS_SDK_RE = re.compile(r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)"""
                        r"""['"](?:@modelcontextprotocol/[\w.-]+(?:/[^'"\n]*)?|fastmcp)['"]""")
_SERVER_CLASSES = {"FastMCP", "Server", "McpServer", "MCPServer"}
_PLURAL = {"tool": "tools", "prompt": "prompts", "resource": "resources"}

# An item: [kind, name, field, text, line]; kind is tool | prompt | resource | server.
Item = list


# --------------------------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------------------------

def _py_str(node: ast.AST | None) -> str | None:
    """A string the code spells out: a literal, or literals joined with `+`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _py_str(node.left), _py_str(node.right)
        return left + right if left is not None and right is not None else None
    return None


def _called(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _kwarg(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _docstring(fn: ast.AST) -> tuple[str, int]:
    text = ast.get_docstring(fn, clean=True) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
    body = getattr(fn, "body", None)
    return (text or ""), (body[0].lineno if text and body else getattr(fn, "lineno", 0))


def _field_descriptions(fn: ast.AST) -> list[tuple[str, str, int]]:
    """(parameter, description, line) from `Field(description=…)` in a parameter's annotation or
    default (`Annotated[str, Field(description=…)]`, `x: str = Field(description=…)`)."""
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    a = fn.args
    positional = a.posonlyargs + a.args
    defaults: dict[str, ast.AST] = dict(zip([p.arg for p in positional[len(positional) - len(a.defaults):]],
                                            a.defaults))
    defaults.update({p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})
    out = []
    for param in positional + a.kwonlyargs:
        for part in (param.annotation, defaults.get(param.arg)):
            if part is None:
                continue
            for node in ast.walk(part):
                if isinstance(node, ast.Call) and _called(node.func) == "Field":
                    value = _kwarg(node, "description")
                    text = _py_str(value)
                    if text is not None:
                        out.append((param.arg, text, value.lineno))
    return out


def _schema_descriptions(schema: ast.AST | None) -> list[tuple[str, str, int]]:
    """(property, description, line) from the `properties` of a JSON-schema dict literal."""
    if not isinstance(schema, ast.Dict):
        return []
    out = []
    for key, value in zip(schema.keys, schema.values):
        if _py_str(key) != "properties" or not isinstance(value, ast.Dict):
            continue
        for pkey, pvalue in zip(value.keys, value.values):
            name = _py_str(pkey)
            if name is None or not isinstance(pvalue, ast.Dict):
                continue
            for dkey, dvalue in zip(pvalue.keys, pvalue.values):
                text = _py_str(dvalue) if _py_str(dkey) == "description" else None
                if text is not None:
                    out.append((name, text, dvalue.lineno))
    return out


def _fn_items(kind: str, name: str, fn: ast.AST, description: ast.AST | None) -> list[Item]:
    text = _py_str(description)
    if text is not None:
        items = [[kind, name, "description", text, description.lineno]]
    else:
        doc, line = _docstring(fn)
        items = [[kind, name, "description", doc, line]]
    items += [[kind, name, f"params.{p}", t, ln] for p, t, ln in _field_descriptions(fn)]
    return items


def _python(text: str) -> list[dict[str, Any]]:
    if not _PY_SDK_RE.search(text):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    servers: dict[str, dict[str, Any]] = {}

    def server(var: str, line: int) -> dict[str, Any]:
        if var not in servers:
            servers[var] = {"name": None, "line": line, "items": []}
        return servers[var]

    defs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    constructed: list[str] = []
    loose: list[Item] = []  # Tool(...) objects: they belong to the file's server
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call) \
                and _called(node.value.func) in _SERVER_CLASSES:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            var = next((t.id for t in targets if isinstance(t, ast.Name)), None)
            if var is None:
                continue
            call = node.value
            rec = server(var, node.lineno)
            rec["line"] = node.lineno
            rec["name"] = _py_str(call.args[0]) if call.args else _py_str(_kwarg(call, "name"))
            constructed.append(var)
            instructions = _kwarg(call, "instructions")
            if _py_str(instructions) is not None:
                rec["items"].append(["server", "", "instructions", _py_str(instructions), instructions.lineno])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                call = dec if isinstance(dec, ast.Call) else None
                target = dec.func if call else dec
                if not (isinstance(target, ast.Attribute) and target.attr in _PLURAL
                        and isinstance(target.value, ast.Name)):
                    continue
                name = (_py_str(_kwarg(call, "name")) if call else None) or node.name
                server(target.value.id, dec.lineno)["items"] += _fn_items(
                    target.attr, name, node, _kwarg(call, "description") if call else None)
        elif isinstance(node, ast.Call):
            called = _called(node.func)
            if called in ("add_tool", "add_prompt") and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) and node.args and isinstance(node.args[0], ast.Name):
                fn = defs.get(node.args[0].id)
                if fn is not None:
                    kind = "tool" if called == "add_tool" else "prompt"
                    name = _py_str(_kwarg(node, "name")) or fn.name
                    server(node.func.value.id, node.lineno)["items"] += _fn_items(
                        kind, name, fn, _kwarg(node, "description"))
            elif called in ("Tool", "Prompt", "Resource"):
                name = _py_str(_kwarg(node, "name"))
                if name is None:
                    continue
                kind = called.lower()
                description = _kwarg(node, "description")
                text = _py_str(description)
                loose.append([kind, name, "description", text or "",
                              description.lineno if text is not None else node.lineno])
                for p, t, ln in _schema_descriptions(_kwarg(node, "inputSchema")):
                    loose.append([kind, name, f"params.{p}", t, ln])
                arguments = _kwarg(node, "arguments")
                for arg in arguments.elts if isinstance(arguments, (ast.List, ast.Tuple)) else []:
                    if isinstance(arg, ast.Call):
                        aname, adesc = _py_str(_kwarg(arg, "name")), _kwarg(arg, "description")
                        if aname and _py_str(adesc) is not None:
                            loose.append([kind, name, f"params.{aname}", _py_str(adesc), adesc.lineno])
    if loose:
        owner = constructed[0] if len(constructed) == 1 else "\0file"
        server(owner, loose[0][4])["items"] += loose
    return [dict(rec, language="python") for rec in servers.values() if rec["items"] or rec["name"]]


# --------------------------------------------------------------------------------------------
# JavaScript / TypeScript
# --------------------------------------------------------------------------------------------

_JS_ESCAPE_RE = re.compile(r"\\(u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r\n|.)", re.S)
_JS_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0",
                      "\n": "", "\r\n": "", "\r": "", "\u2028": "", "\u2029": ""}
_IDENT = r"[A-Za-z_$][\w$]*"
_JS_SERVER_RE = re.compile(r"(?:\b(?:const|let|var|private|public|protected|readonly)\s+|\bthis\s*\.\s*)("
                           + _IDENT + r")\s*(?::[^=;\n]+)?=\s*new\s+(?:" + "|".join(sorted(_SERVER_CLASSES))
                           + r")\s*\(")
# `this.server.tool(…)` names the server `server`
_JS_CALL_RE = re.compile(r"(?<![\w$])(" + _IDENT + r")\s*\.\s*(tool|registerTool|prompt|registerPrompt|resource|"
                         r"registerResource|addTool|addPrompt|addResource)\s*\(")
_JS_DESCRIBE_RE = re.compile(r"\.\s*describe\s*\(")
_JS_CONST_RE = re.compile(r"\b(?:const|let|var)\s+(" + _IDENT + r")\s*(?::[^=;\n]+)?=\s*")
_JS_ZOD_KEY_RE = re.compile(r"(?:^|[{,\s])[\"']?(" + _IDENT + r")[\"']?\s*:\s*z\s*\.")
_JS_SCHEMA_RE = re.compile(r"(?:^|[{,\s])[\"']?inputSchema[\"']?\s*:")


def _js_unescape(body: str) -> str:
    def one(m: re.Match[str]) -> str:
        e = m.group(1)
        if e in _JS_SIMPLE_ESCAPES:
            return _JS_SIMPLE_ESCAPES[e]
        if e[0] == "u":
            code = int(e[2:-1] if e[1] == "{" else e[1:], 16)
            return chr(code) if code <= 0x10FFFF else ""
        if e[0] == "x" and len(e) == 3:
            return chr(int(e[1:], 16))
        return e

    return _JS_ESCAPE_RE.sub(one, body)


def _string_end(text: str, i: int) -> tuple[int, bool]:
    """`text[i]` is a quote: (index just past the closing quote, whether it is a template literal
    with a `${…}` substitution)."""
    q = text[i]
    j, n = i + 1, len(text)
    substituted = False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == q:
            return j + 1, substituted
        if q != "`" and c == "\n":
            return j, substituted  # an unterminated string ends at the line
        if q == "`" and c == "$" and text.startswith("${", j):
            substituted = True
            depth, j = 1, j + 2
            while j < n and depth:
                c = text[j]
                if c in "'\"`":
                    j = _string_end(text, j)[0]
                    continue
                depth += c == "{"
                depth -= c == "}"
                j += 1
            continue
        j += 1
    return n, substituted


_JS_SKIP_RE = re.compile(r"//|/\*|['\"`]")
_JS_PLAIN_STRING_RE = {q: re.compile(q + r"(?:\\.|[^" + q + r"\\\n])*" + q + "?") for q in "'\""}
_NOT_NEWLINE_RE = re.compile(r"[^\n]")


def _blank(s: str) -> str:
    return _NOT_NEWLINE_RE.sub(" ", s)


def _mask(text: str) -> str:
    """The code with comments and the inside of strings blanked (same length, newlines kept), so
    that call sites, braces and commas are found only where they are code."""
    out: list[str] = []
    pos, n = 0, len(text)
    while True:
        m = _JS_SKIP_RE.search(text, pos)
        if not m:
            out.append(text[pos:])
            return "".join(out)
        i, tok = m.start(), m.group(0)
        out.append(text[pos:i])
        if tok == "//":
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(" " * (end - i))
        elif tok == "/*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append(_blank(text[i:end]))
        else:
            end = _JS_PLAIN_STRING_RE[tok].match(text, i).end() if tok != "`" else _string_end(text, i)[0]
            body = text[i + 1:end]
            closed = end - i >= 2 and body.endswith(tok)
            out.append(tok + _blank(body[:-1] if closed else body) + (tok if closed else ""))
        pos = end


def _args(masked: str, start: int, limit: int = 200_000) -> list[tuple[int, int]]:
    """Spans of the top-level arguments of a call whose `(` ends just before `start`."""
    spans: list[tuple[int, int]] = []
    depth, seg, i = 0, start, start
    end = min(len(masked), start + limit)
    while i < end:
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                spans.append((seg, i))
                return [(a, b) for a, b in spans if masked[a:b].strip()]
            depth -= 1
        elif c == "," and depth == 0:
            spans.append((seg, i))
            seg = i + 1
        i += 1
    return []


def _close(masked: str, i: int) -> int:
    """The index of the bracket that closes the one at `i`; -1 when there is none."""
    depth = 0
    for j in range(i, len(masked)):
        c = masked[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return -1


def _constants(text: str, masked: str) -> dict[str, tuple[int, int]]:
    """`const name = "echo"` and `const config = {…}`: the span of each such value, by name, so
    that `server.registerTool(name, config, …)` reads like the literal call."""
    out: dict[str, tuple[int, int]] = {}
    for m in _JS_CONST_RE.finditer(masked):
        v = m.end()
        if v >= len(masked):
            continue
        if masked[v] == "{":
            end = _close(masked, v)
            if end > 0:
                out.setdefault(m.group(1), (v, end + 1))
        elif text[v] in "'\"`":
            end = v
            while end < len(masked) and masked[end] not in ";\n":
                end += 1
            got = _value(text, masked, v, end)
            if got is None:  # a value that runs over several lines: up to the statement's end
                end = masked.find(";", v)
                end = len(masked) if end < 0 else end
            out.setdefault(m.group(1), (v, end))
    return out


def _deref(text: str, consts: dict[str, tuple[int, int]], a: int, b: int) -> tuple[int, int]:
    name = text[a:b].strip()
    return consts.get(name, (a, b)) if re.fullmatch(_IDENT, name) else (a, b)


def _value(text: str, masked: str, a: int, b: int) -> tuple[str, int] | None:
    """(string, offset) when text[a:b] is string literals joined with `+`; None otherwise."""
    parts: list[str] = []
    first = None
    i = a
    while True:
        while i < b and masked[i].isspace():
            i += 1
        if i >= b or text[i] not in "'\"`":
            return None
        end, substituted = _string_end(text, i)
        if substituted or end > b:
            return None
        parts.append(_js_unescape(text[i + 1:end - 1]))
        first = i + 1 if first is None else first
        i = end
        while i < b and masked[i].isspace():
            i += 1
        if i >= b:
            return "".join(parts), first
        if masked[i] != "+":
            return None
        i += 1


def _props(text: str, masked: str, a: int, b: int) -> dict[str, tuple[int, int]]:
    """Top-level `key: value` spans of the object literal in text[a:b] (an argument span)."""
    while a < b and masked[a].isspace():
        a += 1
    if a >= b or masked[a] != "{":
        return {}
    out: dict[str, tuple[int, int]] = {}
    for sa, sb in _args(masked, a + 1):
        seg = masked[sa:sb]
        lead = len(seg) - len(seg.lstrip())
        key_at = sa + lead
        if text[key_at:key_at + 1] in "'\"":
            kend, _ = _string_end(text, key_at)
            key = text[key_at + 1:kend - 1]
        else:
            m = re.match(_IDENT, text[key_at:sb])
            if not m:
                continue
            key, kend = m.group(0), key_at + m.end()
        rest = masked[kend:sb]
        colon = len(rest) - len(rest.lstrip())
        if rest[colon:colon + 1] != ":":
            continue
        out.setdefault(key, (kend + colon + 1, sb))
    return out


def _prop_text(text: str, masked: str, props: dict[str, tuple[int, int]], key: str) -> tuple[str, int] | None:
    span = props.get(key)
    return _value(text, masked, *span) if span else None


def _describes(text: str, masked: str, a: int, b: int, kind: str, name: str) -> list[Item]:
    items = []
    for m in _JS_DESCRIBE_RE.finditer(masked, a, b):
        spans = _args(masked, m.end())
        got = _value(text, masked, *spans[0]) if spans else None
        if got is None:
            continue
        keys = _JS_ZOD_KEY_RE.findall(masked, a, m.start())
        param = keys[-1] if keys else "param"
        items.append([kind, name, f"params.{param}", got[0], line_at(text, got[1])])
    return items


def _item(kind: str, name: str, got: tuple[str, int] | None, text: str, fallback: int) -> Item:
    return [kind, name, "description", got[0] if got else "", line_at(text, got[1] if got else fallback)]


def _javascript(text: str) -> list[dict[str, Any]]:
    if not _JS_SDK_RE.search(text):
        return []
    masked = _mask(text)
    servers: dict[str, dict[str, Any]] = {}
    taken: list[tuple[int, int]] = []

    def server(var: str, offset: int) -> dict[str, Any]:
        if var not in servers:
            servers[var] = {"name": None, "line": line_at(text, offset), "items": []}
        return servers[var]

    constructed: list[str] = []
    for m in _JS_SERVER_RE.finditer(masked):
        rec = server(m.group(1), m.start())
        rec["line"] = line_at(text, m.start())
        constructed.append(m.group(1))
        for a, b in _args(masked, m.end())[:2]:
            props = _props(text, masked, a, b)
            got = _prop_text(text, masked, props, "name")
            if got and rec["name"] is None:
                rec["name"] = got[0]
            got = _prop_text(text, masked, props, "instructions")
            if got:
                rec["items"].append(["server", "", "instructions", got[0], line_at(text, got[1])])

    consts = _constants(text, masked)
    for m in _JS_CALL_RE.finditer(masked):
        var, method = m.group(1), m.group(2)
        spans = _args(masked, m.end())
        if not spans:
            continue
        kind = method.lower().replace("register", "").replace("add", "")
        # an argument given as a constant (`registerTool(name, config, …)`) reads as its value
        args = [_deref(text, consts, a, b) for a, b in spans]
        if method.startswith("add"):  # fastmcp: addTool({name, description, parameters, execute})
            props = _props(text, masked, *args[0])
            got = _prop_text(text, masked, props, "name")
            if not got:
                continue
            name = got[0]
            items = [_item(kind, name, _prop_text(text, masked, props, "description"), text, m.start())]
            items += _describes(text, masked, args[0][0], args[0][1], kind, name)
            read = args[:1]
        else:
            got = _value(text, masked, *args[0])
            if not got:
                continue
            name = got[0]
            read = args[1:-1] if len(args) > 1 else []  # the last argument is the handler
            if method.startswith("register") or kind == "resource":
                config = next((p for p in (_props(text, masked, a, b) for a, b in read) if p), {})
                description = _prop_text(text, masked, config, "description")
            else:  # tool(name, description?, schema?, handler)
                description = _value(text, masked, *read[0]) if read else None
            items = [_item(kind, name, description, text, m.start())]
            for a, b in read:
                items += _describes(text, masked, a, b, kind, name)
        server(var, m.start())["items"] += items
        taken += [(m.start(), spans[-1][1]), *read]

    def owner() -> str:
        if len(constructed) == 1:
            return constructed[0]
        return next(iter(servers)) if len(servers) == 1 else "\0file"

    loose: list[Item] = []
    # zod schemas defined apart from the call that uses them (`inputSchema: EchoSchema`)
    for m in _JS_DESCRIBE_RE.finditer(masked):
        if any(a <= m.start() < b for a, b in taken):
            continue
        spans = _args(masked, m.end())
        got = _value(text, masked, *spans[0]) if spans else None
        if got is None:
            continue
        keys = _JS_ZOD_KEY_RE.findall(masked, max(0, m.start() - 400), m.start())
        loose.append(["schema", "", f"params.{keys[-1] if keys else 'param'}", got[0], line_at(text, got[1])])
    for m in _JS_SCHEMA_RE.finditer(masked):
        at = m.start()
        if any(a <= at < b for a, b in taken):
            continue
        depth, start = 0, None
        for j in range(at, -1, -1):
            c = masked[j]
            if c == "}":
                depth += 1
            elif c == "{":
                if depth == 0:
                    start = j
                    break
                depth -= 1
        if start is None:
            continue
        spans = _args(masked, start + 1)
        if not spans:
            continue
        end = spans[-1][1]
        props = _props(text, masked, start, end + 1)
        got = _prop_text(text, masked, props, "name")
        if not got:
            continue
        loose.append(_item("tool", got[0], _prop_text(text, masked, props, "description"), text, start))
        taken.append((start, end))
    if loose and (servers or any(it[0] != "schema" for it in loose)):  # a schema alone is not a server
        server(owner(), 0)["items"] += loose
    return [dict(rec, language="javascript") for rec in servers.values() if rec["items"] or rec["name"]]


# --------------------------------------------------------------------------------------------
# Components and findings
# --------------------------------------------------------------------------------------------

def servers_in(text: str, suffix: str) -> list[dict[str, Any]]:
    """The MCP servers a source file defines: [{name, line, language, items}], each item
    [kind, name, field, text, line]. Empty for a file that does not import an MCP SDK."""
    suffix = suffix.lower()
    if suffix in _PY:
        if "mcp" not in text:
            return []
        found = _python(text)
    elif suffix in _JS:
        if "modelcontextprotocol" not in text and "fastmcp" not in text:
            return []
        found = _javascript(text)
    else:
        return []
    for rec in found:
        rec["items"] = sorted(([k, n, f, t[:MAX_TEXT], ln] for k, n, f, t, ln in rec["items"]),
                              key=lambda it: it[4])
    return found


def _field(kind: str, name: str, field: str) -> str:
    if kind == "server":
        return f"server.{field}"
    return field if kind == "schema" else f"{_PLURAL[kind]}[{name}].{field}"


def tool_list_hash(items: list[Item]) -> str:
    """Over what the agent is told (kind, name, field, text), not where it stands in the file."""
    canon = sorted([k, n, f, t] for k, n, f, t, _ in items)
    blob = json.dumps(canon, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


_MANIFESTS = ("package.json", "pyproject.toml", "setup.py", "setup.cfg")


def _package_dir(root: Path, rel: str, cache: dict[str, bool]) -> str:
    """The nearest folder above `rel` with a package manifest; "" for the scanned root."""
    parts = rel.split("/")[:-1]
    for i in range(len(parts), 0, -1):
        d = "/".join(parts[:i])
        if d not in cache:
            cache[d] = any((root / d / m).is_file() for m in _MANIFESTS)
        if cache[d]:
            return d
    return ""


def _fold(root: Path, found: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """One server per definition, except that the tools a package registers in files of their own
    (`registerEchoTool(server)` in `tools/echo.ts`) join the one named server that package builds,
    or, when it names none, one server named after the package folder."""
    cache: dict[str, bool] = {}
    by_package: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for rel, rec in sorted(found, key=lambda pair: pair[0]):
        by_package.setdefault(_package_dir(root, rel, cache), []).append((rel, rec))

    def server(rel: str, rec: dict[str, Any], name: str | None) -> dict[str, Any]:
        return {"name": name or rel, "language": rec["language"], "locations": [(rel, rec["line"])],
                "items": [(rel, it) for it in rec["items"]]}

    out: list[dict[str, Any]] = []
    for package, members in by_package.items():
        named = [(rel, rec) for rel, rec in members if rec["name"]]
        nameless = [(rel, rec) for rel, rec in members if not rec["name"]]
        servers = [server(rel, rec, rec["name"]) for rel, rec in named]
        if nameless and len(named) <= 1 and (named or len(nameless) > 1):
            if named:
                target = servers[0]
            else:
                target = server(*nameless[0], package or root.name)
                target["items"], target["locations"] = [], []
                servers.append(target)
            for rel, rec in nameless:
                target["locations"].append((rel, rec["line"]))
                target["items"] += [(rel, it) for it in rec["items"]]
        else:
            servers += [server(rel, rec, None) for rel, rec in nameless]
        out += servers
    return out


def _component(srv: dict[str, Any]) -> Component:
    items = [it for _, it in srv["items"]]
    props: dict[str, Any] = {"defined_in": "code", "language": srv["language"]}
    for kind, plural in _PLURAL.items():
        names = list(dict.fromkeys(n for k, n, *_ in items if k == kind))
        if names:
            props[plural] = names[:MAX_LISTED]
    props["tool_list_hash"] = tool_list_hash(items)
    return Component(name=str(srv["name"])[:200], ctype="mcp-server", source="code-ref",
                     locations=[Location(rel, line) for rel, line in srv["locations"]], properties=props)


def analyze(root: Path, files: list[Path]) -> tuple[list[Component], list[Finding]]:
    root = Path(root)
    found: list[tuple[str, dict[str, Any]]] = []
    for f in files:
        path = f if f.is_absolute() else root / f
        suffix = path.suffix.lower()
        if suffix not in _PY and suffix not in _JS:
            continue
        rel = rel_posix(path, root)
        if is_test_path(rel):
            continue
        try:
            text = read_text(path, max_bytes=MAX_BYTES)
        except (OSError, TooLarge):
            continue
        if "mcp" not in text and "modelcontextprotocol" not in text:
            continue
        found += [(rel, rec) for rec in scancache.memo("mcpcode", text, lambda t: servers_in(t, suffix),
                                                       variant="py" if suffix in _PY else "js")]
    components: list[Component] = []
    findings: list[Finding] = []
    for srv in _fold(root, found):
        comp = _component(srv)
        components.append(comp)
        for rel, (kind, name, field, text, line) in srv["items"]:
            if text:
                findings += textrules.poison_findings(text, "ait.mcp", comp, Location(rel, line),
                                                      _field(kind, name, field))
    return components, findings
