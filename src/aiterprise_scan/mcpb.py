"""MCP bundles: `manifest.json` of an MCPB (`.mcpb`) or legacy DXT (`.dxt`) extension (design doc 13 §5.3 (c)).

A bundle manifest declares how the server is launched (`server.mcp_config`) and, unlike an agent
config, the tool and prompt descriptions the agent will read. Both are judged with the same rules
as agent configs: command rules on the launch line, poisoning patterns on every description.
Nothing is launched.
"""

from __future__ import annotations

from typing import Any

from . import textrules
from .model import Component, Finding, Location


def is_bundle_manifest(doc: Any) -> bool:
    """MCPB/DXT manifests carry a string `manifest_version` (or `dxt_version`) and a `server` object;
    browser-extension manifests use an integer `manifest_version` and have no `server`."""
    if not isinstance(doc, dict) or not isinstance(doc.get("server"), dict):
        return False
    version = doc.get("manifest_version", doc.get("dxt_version"))
    return isinstance(version, str) and bool(doc.get("name"))


def _texts(doc: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key in ("description", "long_description"):
        if isinstance(doc.get(key), str):
            out.append((key, doc[key]))
    for kind in ("tools", "prompts"):
        for i, item in enumerate(doc.get(kind) or []):
            if not isinstance(item, dict):
                continue
            label = str(item.get("name") or i)
            for key in ("description", "text"):
                if isinstance(item.get(key), str):
                    out.append((f"{kind}[{label}].{key}", item[key]))
    for key, item in (doc.get("user_config") or {}).items() if isinstance(doc.get("user_config"), dict) else []:
        if isinstance(item, dict) and isinstance(item.get("description"), str):
            out.append((f"user_config.{key}.description", item["description"]))
    return out


def analyze_manifest(doc: dict, location: str, bundle: str) -> tuple[Component, list[Finding]]:
    """`bundle`: mcpb | dxt | manifest (an unpacked bundle directory)."""
    server = doc.get("server") or {}
    cfg = server.get("mcp_config") if isinstance(server.get("mcp_config"), dict) else {}
    command = cfg.get("command") if isinstance(cfg.get("command"), str) else None
    args = [str(a) for a in cfg.get("args") or [] if isinstance(a, (str, int, float))]
    tools = [str(t.get("name")) for t in doc.get("tools") or [] if isinstance(t, dict) and t.get("name")]
    author = doc.get("author") if isinstance(doc.get("author"), dict) else {}
    props: dict[str, Any] = {
        "bundle": bundle,
        "manifest_version": doc.get("manifest_version") or doc.get("dxt_version"),
        "server_type": server.get("type"),
        "entry_point": server.get("entry_point"),
        "tools": tools[:200],
    }
    if author.get("name"):
        props["author"] = str(author["name"])[:200]
    if doc.get("tools_generated") is True:
        props["tools_generated"] = True  # the real tool list exists only at runtime
    if command:
        props["command"] = command
    comp = Component(
        name=str(doc.get("name"))[:200],
        ctype="mcp-server",
        version=str(doc["version"])[:64] if isinstance(doc.get("version"), str) else None,
        locations=[Location(location)],
        source="config",
        properties={k: v for k, v in props.items() if v not in (None, [], "")},
    )
    loc = Location(location)
    line = " ".join([command or "", *args]).strip()
    findings = textrules.command_findings(line, "ait.mcp", comp, loc)
    for field, text in _texts(doc):
        findings += textrules.poison_findings(text, "ait.mcp", comp, loc, field)
    return comp, findings
