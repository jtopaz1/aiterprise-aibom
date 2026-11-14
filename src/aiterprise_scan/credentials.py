"""SecDB credentials for this machine (design doc 13 §4.8, `14a` §3.1).

Order of precedence:
1. `AITERPRISE_API_KEY` in the environment (CI: a key from the CI secret store);
2. an API key saved by `aiterprise-scan login`;
3. an anonymous install token saved by `aiterprise-scan login --install`.

A key is never embedded in the tool and never printed: `mask()` shows its prefix and last four
characters only. Saved secrets live in `~/.aiterprise/credentials.json` (override the directory
with `AITERPRISE_HOME`). On Windows they are encrypted for the current user with DPAPI; elsewhere
the file is created readable by its owner only (mode 0600).
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

ENV_KEY = "AITERPRISE_API_KEY"
FILE_NAME = "credentials.json"


@dataclass
class Credential:
    kind: str  # api_key | install_token
    secret: str
    origin: str  # env | stored
    install_id: str | None = None

    @property
    def masked(self) -> str:
        return mask(self.secret)


def home() -> Path:
    env = os.environ.get("AITERPRISE_HOME")
    return Path(env) if env else Path.home() / ".aiterprise"


def mask(secret: str) -> str:
    if not secret:
        return ""
    head = secret[: secret.find("_", secret.find("_") + 1) + 1] if secret.count("_") >= 2 else secret[:4]
    return f"{head}…{secret[-4:]}" if len(secret) > len(head) + 8 else f"{head}…"


# --------------------------------------------------------------------------------------------
# Protection at rest
# --------------------------------------------------------------------------------------------

def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = Blob()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if protect:
        fn = crypt32.CryptProtectData
        fn.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.POINTER(Blob), ctypes.c_void_p,
                       ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = fn(ctypes.byref(blob_in), "aiterprise-scan", None, None, None, flags, ctypes.byref(blob_out))
    else:
        fn = crypt32.CryptUnprotectData
        fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob), ctypes.c_void_p,
                       ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = fn(ctypes.byref(blob_in), None, None, None, None, flags, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _seal(secret: str) -> dict:
    if sys.platform == "win32":
        try:
            return {"dpapi": base64.b64encode(_dpapi(secret.encode("utf-8"), True)).decode("ascii")}
        except OSError:
            pass
    return {"plain": secret}


def _open(sealed: dict) -> str | None:
    if "dpapi" in sealed:
        try:
            return _dpapi(base64.b64decode(sealed["dpapi"]), False).decode("utf-8")
        except (OSError, ValueError):
            return None  # another user or machine: unreadable, treated as absent
    value = sealed.get("plain")
    return value if isinstance(value, str) else None


# --------------------------------------------------------------------------------------------
# File
# --------------------------------------------------------------------------------------------

def _path() -> Path:
    return home() / FILE_NAME


def _read() -> dict:
    try:
        doc = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _write(doc: dict) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save_api_key(key: str) -> None:
    doc = _read()
    doc["api_key"] = {"secret": _seal(key), "saved_at": _now()}
    _write(doc)


def save_install(token: str, install_id: str, channel: str) -> None:
    doc = _read()
    doc["install"] = {"secret": _seal(token), "install_id": install_id, "channel": channel, "saved_at": _now()}
    _write(doc)


def clear(which: str = "all") -> bool:
    doc = _read()
    removed = False
    for key in (("api_key", "install") if which == "all" else (which,)):
        removed = doc.pop(key, None) is not None or removed
    if doc:
        _write(doc)
    else:
        try:
            _path().unlink()
        except FileNotFoundError:
            pass
    return removed


def load() -> Credential | None:
    env = os.environ.get(ENV_KEY, "").strip()
    if env:
        return Credential("api_key", env, "env")
    doc = _read()
    if isinstance(doc.get("api_key"), dict):
        secret = _open(doc["api_key"].get("secret") or {})
        if secret:
            return Credential("api_key", secret, "stored")
    if isinstance(doc.get("install"), dict):
        secret = _open(doc["install"].get("secret") or {})
        if secret:
            return Credential("install_token", secret, "stored", doc["install"].get("install_id"))
    return None
