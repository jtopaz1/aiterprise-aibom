"""Local scan history for the UI (`~/.aiterprise/history/`): JSON reports plus a small summary each.

Reports are stored as `aiterprise-scan` JSON documents exactly as `--format json` writes them.
Nothing leaves the machine. `diff` compares two reports by finding fingerprint and component.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
from pathlib import Path, PureWindowsPath

from . import credentials

_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")


def history_dir() -> Path:
    return credentials.home() / "history"


def project_of(doc: dict) -> str:
    target = str(doc.get("target") or "").rstrip("\\/")
    return PureWindowsPath(target).name or target or "scan"


def _meta(sid: str, doc: dict) -> dict:
    s = doc.get("summary") or {}
    return {"id": sid, "target": doc.get("target"), "project": project_of(doc), "started_at": doc.get("started_at"),
            "mode": doc.get("mode"), "exit_code": doc.get("exit_code"), "components": s.get("components", 0),
            "ai_components": s.get("ai_components", 0), "findings": s.get("findings", len(doc.get("findings") or [])),
            "severity": s.get("severity") or {}}


def save(doc: dict) -> str:
    d = history_dir()
    d.mkdir(parents=True, exist_ok=True)
    started = str(doc.get("started_at") or "")
    try:
        t = dt.datetime.fromisoformat(started.replace("Z", "+00:00"))
    except ValueError:
        t = dt.datetime.now(dt.timezone.utc)
    sid = t.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    tmp = d / f".{sid}.tmp"
    tmp.write_text(json.dumps(doc), encoding="utf-8")
    os.replace(tmp, d / f"{sid}.json")
    (d / f"{sid}.meta.json").write_text(json.dumps(_meta(sid, doc)), encoding="utf-8")
    return sid


def _path(sid: str, suffix: str = ".json") -> Path:
    if not isinstance(sid, str) or not _ID.match(sid):
        raise KeyError(sid)
    return history_dir() / f"{sid}{suffix}"


def load(sid: str) -> dict:
    try:
        return json.loads(_path(sid).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise KeyError(sid) from None


def delete(sid: str) -> None:
    for suffix in (".json", ".meta.json"):
        try:
            _path(sid, suffix).unlink()
        except FileNotFoundError:
            pass


def list_scans() -> list[dict]:
    out = []
    d = history_dir()
    if not d.is_dir():
        return out
    for p in d.glob("*.meta.json"):
        sid = p.name[: -len(".meta.json")]
        if not _ID.match(sid):
            continue
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return sorted(out, key=lambda m: m["id"], reverse=True)


def previous_of(sid: str) -> str | None:
    """The scan of the same target just before `sid`, if any."""
    scans = list_scans()
    me = next((s for s in scans if s["id"] == sid), None)
    if me is None:
        return None
    older = [s for s in scans if s["id"] < sid and s.get("target") == me.get("target")]
    return older[0]["id"] if older else None


def _component_key(c: dict) -> str:
    version = f"@{c['version']}" if c.get("version") else ""
    return f"{c.get('type', 'library')} {c.get('name', '')}{version}"


def diff(old: dict, new: dict) -> dict:
    before = {f.get("fingerprint"): f for f in old.get("findings") or []}
    after = {f.get("fingerprint"): f for f in new.get("findings") or []}
    comps_before = {_component_key(c) for c in old.get("components") or []}
    comps_after = {_component_key(c) for c in new.get("components") or []}
    return {
        "new": [f for k, f in after.items() if k not in before],
        "fixed": [f for k, f in before.items() if k not in after],
        "unchanged": [f for k, f in after.items() if k in before],
        "components_added": sorted(comps_after - comps_before),
        "components_removed": sorted(comps_before - comps_after),
    }
