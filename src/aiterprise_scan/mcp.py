"""MCP configuration analyzer (design doc 13 C26 / C29 / C31).

Static only (design G8): parse agent config text, resolve launchers to packages,
infer capability scope, and judge command lines and free-text fields with the
shipped rule sets. Nothing is launched, connected to, or executed.
"""

from __future__ import annotations

import os
import re
import sys
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import data, secrets, sources
from .model import (
    OWASP_EXCESSIVE_AGENCY,
    OWASP_PROMPT_INJECTION,
    OWASP_SENSITIVE_INFO,
    OWASP_SUPPLY_CHAIN,
    Component,
    Evidence,
    Finding,
    Location,
    not_analysable,
)
from .textio import TooLarge, line_of, loads_jsonc, read_text
from .walk import rel_posix

# ---------------------------------------------------------------------------
# Rule sets (shared with skills.py)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _command_rules() -> list[dict[str, Any]]:
    rules = data.load("command-rules.json")["rules"]
    for r in rules:
        r["_re"] = re.compile(r["pattern"], re.IGNORECASE)
    return rules


@lru_cache(maxsize=1)
def _poison_rules() -> list[dict[str, Any]]:
    rules = data.load("poison-patterns.json")["rules"]
    for r in rules:
        r["_re"] = re.compile(r["pattern"])  # poison patterns carry their own (?i)
    return rules


def check_command(command_line: str) -> list[dict[str, Any]]:
    """Command rules that fire on `command_line`, with the matched (redacted) span."""
    if not command_line:
        return []
    out: list[dict[str, Any]] = []
    for rule in _command_rules():
        m = rule["_re"].search(command_line)
        if m:
            hit = {k: v for k, v in rule.items() if k != "_re"}
            hit["match"] = secrets.redact_secrets_in(m.group(0))
            hit["span"] = (m.start(), m.end())
            out.append(hit)
    return out


def check_text(text: str) -> list[dict[str, Any]]:
    """Poison patterns that fire on `text`."""
    if not text:
        return []
    out: list[dict[str, Any]] = []
    for rule in _poison_rules():
        m = rule["_re"].search(text)
        if m:
            hit = {k: v for k, v in rule.items() if k != "_re"}
            # Never echo the raw matched text for stego rules; give a safe label.
            if rule["category"] == "steganography":
                hit["match"] = f"<{rule['id']}>"
            else:
                hit["match"] = secrets.redact_secrets_in(m.group(0))[:160]
            hit["span"] = (m.start(), m.end())
            out.append(hit)
    return out


_CONF = {
    "critical": ("malicious", 90),
    "high": ("suspicious", 75),
    "medium": ("suspicious", 55),
    "low": ("suspicious", 40),
    "info": ("benign", 30),
}


# ---------------------------------------------------------------------------
# Config discovery
# ---------------------------------------------------------------------------

_JSON_MCPSERVERS = {  # filename -> kind, for files identified by name alone
    ".mcp.json": "claude-code",
    "claude_desktop_config.json": "claude-desktop",
    "mcp_config.json": "windsurf",
}


def _config_kind(path: Path, root: Path) -> str | None:
    """Return the config kind for a path, or None if it is not an agent config.

    A generic ``mcp.json`` is accepted only when its text contains ``mcpServers``
    (checked by the caller); here it is reported as kind ``generic``.
    """
    rel = rel_posix(path, root)
    parts = rel.split("/")
    name = parts[-1]
    parent = parts[-2] if len(parts) >= 2 else ""

    if name in _JSON_MCPSERVERS:
        return _JSON_MCPSERVERS[name]
    if parent == ".cursor" and name == "mcp.json":
        return "cursor"
    if parent == ".vscode" and name == "mcp.json":
        return "vscode"
    if parent == ".windsurf" and name == "mcp.json":
        return "windsurf"
    if parent == ".codex" and name == "config.toml":
        return "codex"
    if parent == ".gemini" and name == "settings.json":
        return "gemini"
    if parent == ".claude" and name == "settings.json":
        return "claude-settings"
    if name == ".claude.json":
        return "claude-code-user"
    if name == "config.toml" and ".codex" in parts:
        return "codex"
    if name == "mcp_config.json" and "windsurf" in parts:
        return "windsurf"
    if name == "mcp.json":
        return "generic"
    return None


def find_agent_configs(root: Path, files: list[Path]) -> list[Path]:
    """The subset of `files` that are MCP / agent configs."""
    out: list[Path] = []
    for f in files:
        kind = _config_kind(f, root)
        if kind is None:
            continue
        if kind == "generic":
            try:
                if "mcpServers" not in read_text(f):
                    continue
            except (OSError, TooLarge):
                continue
        out.append(f)
    return out


def machine_agent_config_paths() -> list[Path]:
    """Existing per-OS, user-level agent configs (nothing is read here)."""
    home = Path.home()
    candidates: list[Path] = []
    if sys.platform.startswith("win"):
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        candidates += [
            appdata / "Claude" / "claude_desktop_config.json",
            appdata / "Code" / "User" / "mcp.json",
        ]
    elif sys.platform == "darwin":
        asup = home / "Library" / "Application Support"
        candidates += [
            asup / "Claude" / "claude_desktop_config.json",
            asup / "Code" / "User" / "mcp.json",
        ]
    else:
        cfg = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        candidates += [
            cfg / "Claude" / "claude_desktop_config.json",
            cfg / "Code" / "User" / "mcp.json",
        ]
    candidates += [
        home / ".claude.json",
        home / ".claude" / "settings.json",
        home / ".cursor" / "mcp.json",
        home / ".codex" / "config.toml",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        home / ".gemini" / "settings.json",
    ]
    out: list[Path] = []
    seen: set[str] = set()
    for p in candidates:
        try:
            if p.is_file():
                key = str(p.resolve()).lower()
                if key not in seen:
                    seen.add(key)
                    out.append(p)
        except OSError:
            continue
    return out


# ---------------------------------------------------------------------------
# Launcher resolution -> package components
# ---------------------------------------------------------------------------

_NPM_FLAGS_WITH_ARG = {"-p", "--package", "-c", "--call"}
_DOCKER_FLAGS_WITH_ARG = {
    "-v", "--volume", "--mount", "-e", "--env", "--env-file", "-p", "--publish", "--name",
    "--network", "--net", "-w", "--workdir", "--user", "-u", "--entrypoint", "--label", "-l",
    "--add-host", "--device", "--cap-add", "--cap-drop", "--security-opt", "--platform",
    "--memory", "-m", "--cpus", "--restart", "--hostname", "-h",
}


def _basename(cmd: str) -> str:
    base = re.split(r"[\\/]", cmd.strip().strip('"'))[-1].lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


def _split_pkg(spec: str, sep: str) -> tuple[str, str | None]:
    """Split a package spec into (name, pinned_version | None)."""
    spec = spec.strip().strip('"')
    if spec.startswith("@"):  # npm scoped: @scope/name[@ver]
        at = spec.find("@", 1)
        if at > 0:
            return spec[:at], spec[at + 1 :] or None
        return spec, None
    if sep == "@":
        name, _, ver = spec.partition("@")
        return name, (ver or None)
    # pip/uv style separators
    for s in ("==", ">=", "<=", "~=", ">", "<", "!="):
        if s in spec:
            name, _, ver = spec.partition(s)
            return name, (ver if s == "==" else None)
    return spec, None


def _first_positional(args: list[str], flags_with_arg: set[str]) -> str | None:
    i = 0
    while i < len(args):
        a = args[i]
        if a in flags_with_arg:
            i += 2
            continue
        if a.startswith("-"):
            if "=" in a:
                i += 1
                continue
            i += 1
            continue
        return a
    return None


def resolve_launcher(command: str | None, args: list[str]) -> dict[str, Any] | None:
    """Resolve a stdio launcher to a package/image, or None if not resolvable.

    Returns {ecosystem, name, version, spec, image?}. ``ecosystem`` is None for
    docker images (no package ecosystem), npm for node launchers, pypi for python.
    """
    if not command:
        return None
    base = _basename(command)
    args = [str(a) for a in args]

    if base in ("npx", "bunx"):
        spec = _first_positional(args, _NPM_FLAGS_WITH_ARG)
        if spec:
            name, ver = _split_pkg(spec, "@")
            return {"ecosystem": "npm", "name": name, "version": ver, "spec": spec}
    if base in ("pnpm", "yarn", "bun") and args and args[0] in ("dlx", "x"):
        spec = _first_positional(args[1:], _NPM_FLAGS_WITH_ARG)
        if spec:
            name, ver = _split_pkg(spec, "@")
            return {"ecosystem": "npm", "name": name, "version": ver, "spec": spec}
    if base == "uvx":
        rest = args
        if "--from" in args:
            idx = args.index("--from")
            if idx + 1 < len(args):
                spec = args[idx + 1]
                name, ver = _split_pkg(spec, "==")
                return {"ecosystem": "pypi", "name": name, "version": ver, "spec": spec}
        spec = _first_positional(rest, {"--with", "--from", "-p", "--python"})
        if spec:
            name, ver = _split_pkg(spec, "==")
            return {"ecosystem": "pypi", "name": name, "version": ver, "spec": spec}
    if base == "pipx" and args and args[0] == "run":
        spec = None
        if "--spec" in args:
            idx = args.index("--spec")
            if idx + 1 < len(args):
                spec = args[idx + 1]
        if spec is None:
            spec = _first_positional(args[1:], {"--spec", "--python", "--pip-args"})
        if spec:
            name, ver = _split_pkg(spec, "==")
            return {"ecosystem": "pypi", "name": name, "version": ver, "spec": spec}
    if base in ("python", "python3", "python2", "py") and "-m" in args:
        idx = args.index("-m")
        if idx + 1 < len(args):
            module = args[idx + 1].split(".")[0]
            return {"ecosystem": "pypi", "name": module, "version": None, "spec": module}
    if base == "docker" and args and args[0] in ("run", "create"):
        image = _first_positional(args[1:], _DOCKER_FLAGS_WITH_ARG)
        if image and not image.startswith("-"):
            name, _, tag = image.rpartition(":")
            if not name or "/" in tag:  # no tag (colon was in a path) -> whole thing is the image
                name, tag = image, None
            return {"ecosystem": None, "name": name, "version": tag or None,
                    "spec": image, "image": image}
    return None


# ---------------------------------------------------------------------------
# Scope inference
# ---------------------------------------------------------------------------

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "powershell", "pwsh", "fish"}
_FS_HINT = re.compile(r"(?i)file[-_]?system|server-filesystem|\bfiles?\b")
_NET_HINT = re.compile(r"(?i)fetch|http|web|browser|playwright|puppeteer|search|brave|crawl|url")
_SECRET_ENV_KEY = re.compile(r"(?i)key|token|secret|password|passwd|credential|auth|apikey")
_HOME_ARGS = {"~", "$HOME", "%USERPROFILE%", "%HOMEPATH%", "/root", "/home", "/users"}


def _infer_scopes(command: str | None, args: list[str], url: str | None,
                  env: dict, transport: str, pkg_name: str | None) -> list[str]:
    scopes: set[str] = set()
    base = _basename(command) if command else ""
    cl = " ".join([command or ""] + [str(a) for a in args])
    name_blob = " ".join(filter(None, [base, pkg_name or "", " ".join(str(a) for a in args)]))

    if base in _SHELLS or "-c" in args or "-e" in args:
        scopes.add("shell")
    if transport in ("http", "sse", "streamable-http") or url:
        scopes.add("network")
    if re.search(r"https?://", cl) or _NET_HINT.search(name_blob):
        scopes.add("network")
    if _FS_HINT.search(name_blob):
        scopes.add("fs-read")
        if not any(str(a).lower() in ("--readonly", "--read-only", "--ro") for a in args):
            scopes.add("fs-write")
    if isinstance(env, dict):
        for k, v in env.items():
            if _SECRET_ENV_KEY.search(str(k)) or secrets.find_secrets(str(v)):
                scopes.add("secrets-env")
                break
    return sorted(scopes)


def _is_broad_fs_path(value: str) -> bool:
    v = value.strip().strip('"').rstrip("/\\")
    if v in ("", "/", "~", "$HOME", "%USERPROFILE%", "%HOMEPATH%"):
        return True
    if re.fullmatch(r"[A-Za-z]:", v) or re.fullmatch(r"[A-Za-z]:[\\/]?", value.strip()):
        return True
    if v.lower() in ("/root", "/home", "/users") or v.lower() in _HOME_ARGS:
        return True
    return False


def _is_local_host(url: str) -> bool:
    m = re.match(r"https?://([^/:]+)", url, re.IGNORECASE)
    host = (m.group(1) if m else "").lower()
    return host in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "host.docker.internal")


# ---------------------------------------------------------------------------
# Free-text field collection
# ---------------------------------------------------------------------------

_TEXT_KEYS = {
    "description", "instructions", "instruction", "prompt", "systemprompt", "system_prompt",
    "system", "summary", "longdescription", "long_description", "note", "notes", "title",
    "context", "readme", "detail", "details", "annotation", "annotations", "tooldescription",
}


def _free_texts(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """(field-path, text) for every free-text string inside a server config."""
    found: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(v, str) and key.lower() in _TEXT_KEYS:
                found.append((path, v))
            elif isinstance(v, (dict, list)):
                found.extend(_free_texts(v, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                found.extend(_free_texts(v, f"{prefix}[{i}]"))
    return found


# ---------------------------------------------------------------------------
# Per-config analysis
# ---------------------------------------------------------------------------


def _finding_from_command(hit: dict, location: Location, comp: Component, prefix: str) -> Finding:
    verdict, conf = _CONF[hit["severity"]]
    maps = [OWASP_SUPPLY_CHAIN]
    if hit["category"] in ("cred", "exfil", "exec", "download-exec"):
        maps = [OWASP_SENSITIVE_INFO, OWASP_SUPPLY_CHAIN]
    return Finding(
        rule_id=f"{prefix}.cmd.{hit['id']}",
        title=f"Dangerous command in {comp.name}: {hit['description']}",
        severity=hit["severity"],
        verdict=verdict,
        confidence=conf,
        component=comp,
        location=location,
        evidence=[Evidence(source="ait-rules", record=hit["id"],
                           detail={"category": hit["category"], "match": secrets.redact_secrets_in(hit["match"])})],
        remediation=hit["remediation"],
        maps_to=maps,
        discriminator=hit["id"],
    )


def _finding_from_poison(hit: dict, location: Location, comp: Component, field: str,
                         prefix: str) -> Finding:
    verdict, conf = _CONF[hit["severity"]]
    verdict = "malicious" if hit["severity"] == "critical" else "suspicious"
    return Finding(
        rule_id=f"{prefix}.desc.{hit['id']}",
        title=f"Prompt poisoning in {comp.name} ({field}): {hit['description']}",
        severity=hit["severity"],
        verdict=verdict,
        confidence=conf,
        component=comp,
        location=location,
        evidence=[Evidence(source="ait-rules", record=hit["id"],
                           detail={"category": hit["category"], "field": field,
                                   "match": secrets.redact_secrets_in(hit["match"])})],
        remediation=hit["remediation"],
        maps_to=[OWASP_PROMPT_INJECTION, OWASP_SUPPLY_CHAIN],
        discriminator=f"{hit['id']}:{field}",
    )


def _parse_config(path: Path, kind: str) -> tuple[Any, str]:
    text = read_text(path)
    if kind == "codex" or path.suffix.lower() == ".toml":
        return tomllib.loads(text), text
    return loads_jsonc(text), text


def _servers_from(data_obj: Any, kind: str) -> dict[str, dict]:
    """Extract the {name: server-config} mapping for a parsed config."""
    servers: dict[str, dict] = {}
    if not isinstance(data_obj, dict):
        return servers
    if kind == "codex":
        ms = data_obj.get("mcp_servers")
        if isinstance(ms, dict):
            for n, cfg in ms.items():
                if isinstance(cfg, dict):
                    servers[str(n)] = cfg
        return servers
    if kind == "vscode":
        ms = data_obj.get("servers") or data_obj.get("mcpServers")
        if isinstance(ms, dict):
            for n, cfg in ms.items():
                if isinstance(cfg, dict):
                    servers[str(n)] = cfg
        return servers
    # json family: mcpServers at top level, plus projects.*.mcpServers (.claude.json)
    ms = data_obj.get("mcpServers") or data_obj.get("servers")
    if isinstance(ms, dict):
        for n, cfg in ms.items():
            if isinstance(cfg, dict):
                servers[str(n)] = cfg
    projects = data_obj.get("projects")
    if isinstance(projects, dict):
        for proj in projects.values():
            if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
                for n, cfg in proj["mcpServers"].items():
                    if isinstance(cfg, dict):
                        servers.setdefault(str(n), cfg)
    return servers


def _hook_commands(data_obj: Any) -> list[str]:
    """Shell commands configured as Claude Code hooks."""
    cmds: list[str] = []
    hooks = data_obj.get("hooks") if isinstance(data_obj, dict) else None
    if not isinstance(hooks, dict):
        return cmds

    def _collect(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "command" and isinstance(node.get("command"), str):
                cmds.append(node["command"])
            elif isinstance(node.get("command"), str) and "type" not in node:
                cmds.append(node["command"])
            for v in node.values():
                _collect(v)
        elif isinstance(node, list):
            for v in node:
                _collect(v)

    _collect(hooks)
    return cmds


def analyze_mcp_config(path: Path, root: Path) -> tuple[list[Component], list[Finding]]:
    """Analyze a single agent config file."""
    rel = rel_posix(path, root)
    kind = _config_kind(path, root) or "generic"
    components: list[Component] = []
    findings: list[Finding] = []

    cfg_comp = Component(
        name=path.name, ctype="mcp-config", source="config",
        locations=[Location(rel, 1)], properties={"agent": kind, "path": rel},
    )
    components.append(cfg_comp)

    try:
        parsed, text = _parse_config(path, kind)
    except Exception as e:  # unreadable, too large or malformed JSON/TOML: record, do not crash
        problem = "unreadable" if isinstance(e, (OSError, TooLarge)) else "parse-error"
        cfg_comp.properties["error"] = f"{problem}: {e.__class__.__name__}"
        findings.append(not_analysable("mcp", rel, f"Agent config {path.name}",
                                       f"{problem}: {e.__class__.__name__}", cfg_comp))
        return components, findings

    # Hooks (settings.json and any config that carries them) run shell commands.
    for hook_cmd in _hook_commands(parsed):
        line = line_of(text, hook_cmd[:40]) or 1
        loc = Location(rel, line)
        for hit in check_command(hook_cmd):
            findings.append(_finding_from_command(hit, loc, cfg_comp, "ait.mcp"))

    servers = _servers_from(parsed, kind)
    for name, scfg in servers.items():
        command = scfg.get("command")
        args = scfg.get("args") or []
        if not isinstance(args, list):
            args = [args]
        args = [str(a) for a in args]
        url = scfg.get("url") or scfg.get("serverUrl") or scfg.get("httpUrl")
        env = scfg.get("env") if isinstance(scfg.get("env"), dict) else {}
        headers = scfg.get("headers") if isinstance(scfg.get("headers"), dict) else {}
        type_ = str(scfg.get("type") or scfg.get("transport") or "").lower()

        if command:
            transport = "stdio"
        elif url:
            transport = type_ if type_ in ("http", "sse", "streamable-http") else (
                "sse" if "sse" in str(url).lower() else "http")
        else:
            transport = type_ or "unknown"

        command_line = " ".join([str(command)] + args) if command else ""
        resolved = resolve_launcher(command, args) if command else None
        pkg_name = resolved["name"] if resolved else None
        scopes = _infer_scopes(command, args, url, env, transport, pkg_name)

        name_line = line_of(text, f'"{name}"') or line_of(text, name) or 1
        loc = Location(rel, name_line)

        props: dict[str, Any] = {
            "transport": transport,
            "config": rel,
            "scopes": scopes,
        }
        if command:
            props["command"] = secrets.redact_secrets_in(str(command))
        if args:
            props["args"] = [secrets.redact_secrets_in(a) for a in args]
        if url:
            props["url"] = secrets.redact_url(str(url))
        if resolved:
            props["resolved_package"] = resolved.get("spec")

        server_comp = Component(
            name=name, ctype="mcp-server", source="config",
            locations=[loc], properties=props,
        )
        components.append(server_comp)

        # Resolved launcher -> library component for the package analyzers to judge.
        if resolved:
            lib_props = {"via_mcp_server": name, "config": rel}
            if resolved.get("image"):
                lib_props["image"] = resolved["image"]
                lib_props["docker"] = True
            if resolved["version"] is None and resolved.get("spec", "").endswith("@latest"):
                lib_props["unpinned"] = "latest"
            lib = Component(
                name=resolved["name"],
                ctype="library",
                version=resolved["version"],
                ecosystem=resolved["ecosystem"],
                source="config",
                locations=[loc],
                properties=lib_props,
            )
            components.append(lib)

        # (1) command rules on the full command line
        for hit in check_command(command_line):
            findings.append(_finding_from_command(hit, loc, server_comp, "ait.mcp"))

        # (2) poison patterns on every free-text field
        for field, value in _free_texts(scfg):
            for hit in check_text(value):
                findings.append(_finding_from_poison(hit, loc, server_comp, field, "ait.mcp"))

        # (3) literal secrets in env / headers / args
        blob_fields: list[tuple[str, str]] = []
        for k, v in env.items():
            blob_fields.append((f"env.{k}", str(v)))
        for k, v in headers.items():
            blob_fields.append((f"headers.{k}", str(v)))
        for i, a in enumerate(args):
            blob_fields.append((f"args[{i}]", a))
        for field, value in blob_fields:
            for sm in secrets.find_secrets(value):
                findings.append(Finding(
                    rule_id=f"ait.secret.{sm.kind}",
                    title=f"Hard-coded credential in {name} ({field})",
                    severity="high",
                    verdict="suspicious",
                    confidence=80,
                    component=server_comp,
                    location=loc,
                    evidence=[Evidence(source="ait-secrets", record=sm.rule_id,
                                       detail={"kind": sm.kind, "field": field,
                                               "redacted": sm.redacted, "digest": sm.digest[:8]})],
                    remediation=("Do not hard-code secrets in an MCP config; reference an "
                                 "environment variable and rotate the exposed value."),
                    maps_to=[OWASP_SENSITIVE_INFO],
                    discriminator=sm.digest[:8],
                ))

        # (4) over-broad filesystem scope
        if _FS_HINT.search(" ".join(filter(None, [name, pkg_name or "", command_line]))):
            for a in args:
                if _is_broad_fs_path(a):
                    findings.append(Finding(
                        rule_id="ait.mcp.scope.broad-filesystem",
                        title=f"Filesystem server {name} granted an over-broad path ({a})",
                        severity="medium",
                        verdict="suspicious",
                        confidence=65,
                        component=server_comp,
                        location=loc,
                        evidence=[Evidence(source="ait-rules", record="scope.broad-filesystem",
                                           detail={"path": a})],
                        remediation=("Scope the filesystem server to a specific project "
                                     "directory, not a drive/home/filesystem root."),
                        maps_to=[OWASP_EXCESSIVE_AGENCY],
                        discriminator=a,
                    ))
                    break

        # plain-http remote URL to a non-local host
        if url and str(url).lower().startswith("http://") and not _is_local_host(str(url)):
            findings.append(Finding(
                rule_id="ait.mcp.net.plain-http",
                title=f"Remote MCP server {name} uses plaintext HTTP",
                severity="medium",
                verdict="suspicious",
                confidence=60,
                component=server_comp,
                location=loc,
                evidence=[Evidence(source="ait-rules", record="net.plain-http",
                                   detail={"url": secrets.redact_url(str(url))})],
                remediation="Use an https:// endpoint; plaintext HTTP exposes traffic and headers.",
                maps_to=[OWASP_SUPPLY_CHAIN],
                discriminator="plain-http",
            ))

    return components, findings


def analyze_mcp(root: Path, files: list[Path], include_machine: bool = False,
                result=None) -> tuple[list[Component], list[Finding]]:
    """Analyze every repo-level agent config (and machine-level ones when asked). Given a `result`,
    records the coverage."""
    components: list[Component] = []
    findings: list[Finding] = []
    seen: set[str] = set()

    for cfg in find_agent_configs(root, files):
        try:
            key = str(cfg.resolve()).lower()
        except OSError:
            key = str(cfg).lower()
        if key in seen:
            continue
        seen.add(key)
        c, f = analyze_mcp_config(cfg, root)
        components.extend(c)
        findings.extend(f)

    if include_machine:
        for p in machine_agent_config_paths():
            try:
                key = str(p.resolve()).lower()
            except OSError:
                key = str(p).lower()
            if key in seen:
                continue
            seen.add(key)
            c, f = analyze_mcp_config(p, root)
            components.extend(c)
            findings.extend(f)

    _count(result, components, findings)
    return components, findings


def analyze_machine_configs(result=None) -> tuple[list[Component], list[Finding]]:
    """Analyze this machine's own agent configs, with no project. Given a `result`, records the
    coverage."""
    components: list[Component] = []
    findings: list[Finding] = []
    for path in machine_agent_config_paths():
        c, f = analyze_mcp_config(path, path.parent)
        components += c
        findings += f
    _count(result, components, findings)
    return components, findings


def _count(result, components: list[Component], findings: list[Finding]) -> None:
    sources.count(result, sources.MCP, (c for c in components if c.ctype == "mcp-server"), findings)
