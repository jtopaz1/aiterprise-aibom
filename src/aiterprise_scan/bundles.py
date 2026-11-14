"""Signed AIT definition bundles: verify, install, roll back (design doc 13 §5.4; `14a` §7).

A bundle directory holds `manifest.json`, `signature.minisig`, the archive the manifest names, and
`signing-keys.json` + `signing-keys.json.minisig`. Verification runs in the contract's order and
any failure refuses the bundle and keeps the last good release:

1. `signing-keys.json` must carry a valid root signature, be newer than the list already held
   (rollback rule) and not be past `expires_at`;
2. the manifest signature must come from a key in that list, and verify over the exact bytes;
3. only then is the manifest parsed: `signing_key_id` must name an active key whose validity
   window covers `created_at`; `release_id` must equal `rel_` + SHA-256(JCS(manifest − release_id));
   domain / format / channel / release must match what was asked for; no downgrade;
4. the archive's size and SHA-256 are checked before it is opened, then it is unpacked
   defensively (no absolute paths, no `..`, regular files only, size caps) and every `files[]`
   entry is checked.

The pinned root key is not published yet (SecDB open point O-23). Until it is, every verify and
install needs `--root-key FILE` (or `AITERPRISE_ROOT_KEY`), and the wheel's bundled data stays in use.

Installed releases live in `~/.aiterprise/defs/<release_id>/`; `state.json` names the active one
and is replaced atomically. At load time each file is re-checked against the installed manifest;
a mismatch falls back to the wheel's copy and is reported in `WARNINGS`.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import os
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import credentials, minisign

DOMAIN = "AIT"
FORMAT = "ait-bundle"
ROOT_KEY_ENV = "AITERPRISE_ROOT_KEY"
DEFS_ENV = "AITERPRISE_DEFS"  # "bundled": ignore installed bundles
ROOT_PUBLIC_KEY: str | None = None  # pinned at the key ceremony (O-23); not published yet
MAX_FILES = 1000
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
WARNINGS: list[str] = []


class BundleError(Exception):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _ts(value: str, what: str) -> dt.datetime:
    try:
        t = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise BundleError(f"{what}: not a timestamp ({value!r})") from None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def jcs(value) -> bytes:
    """RFC 8785 for the manifest's value space (strings, integers, booleans, null, lists, objects)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def release_id(manifest: dict) -> str:
    return "rel_" + hashlib.sha256(jcs({k: v for k, v in manifest.items() if k != "release_id"})).hexdigest()


def root_key(path: Path | None = None) -> minisign.PublicKey:
    if path is None and os.environ.get(ROOT_KEY_ENV):
        path = Path(os.environ[ROOT_KEY_ENV])
    if path is not None:
        try:
            return minisign.parse_public_key(path.read_text(encoding="utf-8"))
        except (OSError, minisign.SignatureError) as err:
            raise BundleError(f"root key {path}: {err}") from None
    if ROOT_PUBLIC_KEY:
        return minisign.parse_public_key(ROOT_PUBLIC_KEY)
    raise BundleError("no root key: SecDB has not published its bundle root key yet (O-23); "
                      f"pass --root-key FILE or set {ROOT_KEY_ENV}")


@dataclass
class SigningKey:
    key: minisign.PublicKey
    not_before: dt.datetime
    not_after: dt.datetime
    status: str


@dataclass
class Verified:
    manifest: dict
    manifest_bytes: bytes
    signature: str
    files: dict[str, bytes]
    keys_issued_at: str
    signing_keys: bytes
    signing_keys_sig: str


def _read(path: Path, binary: bool = True, limit: int = 4 * 1024 * 1024):
    try:
        if path.stat().st_size > limit:
            raise BundleError(f"{path.name} is too large")
        return path.read_bytes() if binary else path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise BundleError(f"{path.name} is missing") from None
    except (OSError, UnicodeDecodeError) as err:
        raise BundleError(f"{path.name}: {err}") from None


def verify_signing_keys(body: bytes, sig: str, root: minisign.PublicKey, held_issued_at: str | None,
                        now: dt.datetime) -> tuple[str, list[SigningKey]]:
    try:
        minisign.verify(root, body, sig)
    except minisign.SignatureError as err:
        raise BundleError(f"signing-keys.json is not signed by the root key: {err}") from None
    try:
        doc = json.loads(body.decode("utf-8"))
    except ValueError as err:
        raise BundleError(f"signing-keys.json: {err}") from None
    if not isinstance(doc, dict) or doc.get("schema_version") != 1 or not isinstance(doc.get("keys"), list):
        raise BundleError("signing-keys.json: unsupported shape")
    issued, expires = _ts(doc.get("issued_at"), "issued_at"), _ts(doc.get("expires_at"), "expires_at")
    if now >= expires:
        raise BundleError(f"signing-keys.json expired at {doc['expires_at']}")
    if held_issued_at and issued < _ts(held_issued_at, "held issued_at"):
        raise BundleError(f"signing-keys.json (issued {doc['issued_at']}) is older than the list already held "
                          f"({held_issued_at}): rollback refused")
    keys = []
    for k in doc["keys"]:
        try:
            pub = minisign.parse_public_key(str(k["public_key"]))
            if pub.key_id_hex != str(k["key_id"]).upper():
                raise BundleError(f"signing key {k['key_id']}: key id does not match its public key")
            keys.append(SigningKey(pub, _ts(k["not_before"], "not_before"), _ts(k["not_after"], "not_after"),
                                   str(k.get("status") or "")))
        except (KeyError, TypeError, minisign.SignatureError) as err:
            raise BundleError(f"signing-keys.json: bad key entry ({err})") from None
    return str(doc["issued_at"]), keys


def _safe_member(name: str) -> str:
    p = PurePosixPath(name)
    if name.startswith(("/", "\\")) or p.is_absolute() or ".." in p.parts or "\\" in name or ":" in name:
        raise BundleError(f"archive member {name!r}: unsafe path")
    return str(p)


def _unpack(blob: bytes, name: str) -> dict[str, bytes]:
    if name.endswith((".tar.gz", ".tgz")):
        raw = gzip.GzipFile(fileobj=io.BytesIO(blob)).read(MAX_TOTAL + 1)
    elif name.endswith(".tar.zst"):
        try:
            from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+
        except ImportError:
            raise BundleError("this Python cannot read .tar.zst bundles (needs 3.14+)") from None
        raw = zstd.decompress(blob)
    elif name.endswith(".tar"):
        raw = blob
    else:
        raise BundleError(f"unsupported archive type: {name}")
    if len(raw) > MAX_TOTAL:
        raise BundleError("archive expands beyond the size cap")
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for i, member in enumerate(tar):
            if i >= MAX_FILES:
                raise BundleError("archive has too many members")
            path = _safe_member(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise BundleError(f"archive member {member.name!r}: not a regular file")
            fh = tar.extractfile(member)
            out[path] = fh.read() if fh else b""
    return out


def verify_dir(path: Path, root: minisign.PublicKey, expect: dict | None = None, keys_issued_at: str | None = None,
               installed_created_at: str | None = None, now: dt.datetime | None = None) -> Verified:
    now = now or _now()
    path = Path(path)
    keys_body = _read(path / "signing-keys.json")
    keys_sig = _read(path / "signing-keys.json.minisig", binary=False)
    issued, keys = verify_signing_keys(keys_body, keys_sig, root, keys_issued_at, now)

    body = _read(path / "manifest.json")
    sig_text = _read(path / "signature.minisig", binary=False)
    try:
        sig_key_id = minisign.parse_signature(sig_text).key_id
    except minisign.SignatureError as err:
        raise BundleError(f"signature.minisig: {err}") from None
    match = [k for k in keys if k.key.key_id == sig_key_id]
    if not match:
        raise BundleError(f"manifest signed by key {minisign.key_id_hex(sig_key_id)}, which is not in signing-keys.json")
    key = match[0]
    try:
        minisign.verify(key.key, body, sig_text)
    except minisign.SignatureError as err:
        raise BundleError(f"manifest signature: {err}") from None

    try:
        manifest = json.loads(body.decode("utf-8"))
    except ValueError as err:
        raise BundleError(f"manifest.json: {err}") from None
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise BundleError("manifest.json: unsupported schema_version")
    if str(manifest.get("signing_key_id", "")).upper() != key.key.key_id_hex:
        raise BundleError("manifest signing_key_id does not name the key that signed it")
    if key.status != "active":
        raise BundleError(f"signing key {key.key.key_id_hex} is {key.status or 'not active'}")
    created = _ts(manifest.get("created_at"), "created_at")
    if not key.not_before <= created <= key.not_after:
        raise BundleError(f"signing key {key.key.key_id_hex}: validity window does not cover created_at")
    if manifest.get("release_id") != release_id(manifest):
        raise BundleError("release_id does not match the manifest (rel_ + SHA-256 of its JCS form)")
    want = {"domain": DOMAIN, "format": FORMAT, **(expect or {})}
    for field in ("release_id", "channel", "domain", "format"):
        if field in want and want[field] is not None and manifest.get(field) != want[field]:
            raise BundleError(f"{field} is {manifest.get(field)!r}, expected {want[field]!r}")
    if installed_created_at and created < _ts(installed_created_at, "installed created_at"):
        raise BundleError(f"created_at {manifest['created_at']} is older than the installed release: downgrade refused")

    arc = manifest.get("archive") or {}
    name = str(arc.get("name") or "")
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise BundleError("manifest archive name is not a plain file name")
    arc_path = path / name
    try:
        size = arc_path.stat().st_size
    except FileNotFoundError:
        raise BundleError(f"archive {name} is missing") from None
    if size != arc.get("bytes") or size > MAX_ARCHIVE:
        raise BundleError(f"archive {name}: size {size} does not match the manifest ({arc.get('bytes')})")
    blob = arc_path.read_bytes()
    if hashlib.sha256(blob).hexdigest() != arc.get("sha256"):
        raise BundleError(f"archive {name}: SHA-256 does not match the manifest")

    members = _unpack(blob, name)
    listed = {}
    for f in manifest.get("files") or []:
        p = _safe_member(str(f.get("path", "")))
        listed[p] = f
    for p in members:
        if p not in listed:
            raise BundleError(f"archive member {p!r} is not listed in the manifest")
    for p, f in listed.items():
        if p not in members:
            raise BundleError(f"{p} is missing from the archive")
        if len(members[p]) != f.get("bytes") or hashlib.sha256(members[p]).hexdigest() != f.get("sha256"):
            raise BundleError(f"{p} does not match its manifest entry")
    return Verified(manifest, body, sig_text, members, issued, keys_body, keys_sig)


# --------------------------------------------------------------------------------------------
# Installed releases
# --------------------------------------------------------------------------------------------

def defs_dir() -> Path:
    return credentials.home() / "defs"


def state() -> dict:
    try:
        doc = json.loads((defs_dir() / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    doc.setdefault("current", None)
    doc.setdefault("history", [])
    doc.setdefault("releases", {})
    return doc


def _write_state(doc: dict) -> None:
    d = defs_dir()
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "state.json.tmp"
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.replace(tmp, d / "state.json")


def install(v: Verified) -> str:
    rid = v.manifest["release_id"]
    d = defs_dir()
    final = d / rid
    if not final.is_dir():
        tmp = d / f".{rid}.tmp"
        if tmp.exists():
            shutil.rmtree(tmp)
        for p, blob in v.files.items():
            target = tmp / PurePosixPath(p)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
        (tmp / "manifest.json").write_bytes(v.manifest_bytes)
        (tmp / "signature.minisig").write_text(v.signature, encoding="utf-8", newline="\n")
        (tmp / "signing-keys.json").write_bytes(v.signing_keys)
        (tmp / "signing-keys.json.minisig").write_text(v.signing_keys_sig, encoding="utf-8", newline="\n")
        os.replace(tmp, final)
    st = state()
    st["history"] = [rid] + [h for h in st["history"] if h != rid]
    st["current"] = rid
    st["keys_issued_at"] = max(filter(None, [st.get("keys_issued_at"), v.keys_issued_at]))
    st["releases"][rid] = {"created_at": v.manifest.get("created_at"), "channel": v.manifest.get("channel"),
                           "installed_at": _now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "files": len(v.files)}
    _write_state(st)
    _active_manifest.cache_clear()
    return rid


def rollback() -> str | None:
    """Make the previous release active (or the wheel's data when there is none). Returns it."""
    st = state()
    cur = st.get("current")
    hist = [h for h in st["history"] if (defs_dir() / h).is_dir()]
    nxt = None
    if cur in hist:
        idx = hist.index(cur)
        nxt = hist[idx + 1] if idx + 1 < len(hist) else None
    st["current"] = nxt
    _write_state(st)
    _active_manifest.cache_clear()
    return nxt


def _active_manifest_uncached(home: str) -> tuple[str, dict] | None:
    st = state()
    rid = st.get("current")
    if not rid:
        return None
    try:
        manifest = json.loads((defs_dir() / rid / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        WARNINGS.append(f"installed release {rid}: manifest unreadable; using the wheel's data")
        return None
    return rid, manifest


class _Cache:
    def __init__(self):
        self.key = None
        self.value = None

    def __call__(self, home: str):
        if self.key != home:
            self.key, self.value = home, _active_manifest_uncached(home)
        return self.value

    def cache_clear(self):
        self.key = None


_active_manifest = _Cache()


def active() -> tuple[str, dict] | None:
    if os.environ.get(DEFS_ENV, "").lower() == "bundled":
        return None
    return _active_manifest(str(credentials.home()))


def installed_file(name: str) -> tuple[str, bytes] | None:
    """(release_id, bytes) of `content/<name>` from the active release, re-checked against its manifest."""
    act = active()
    if act is None:
        return None
    rid, manifest = act
    entry = next((f for f in manifest.get("files") or [] if f.get("path") == f"content/{name}"), None)
    if entry is None:
        return None
    try:
        blob = (defs_dir() / rid / "content" / name).read_bytes()
    except OSError:
        WARNINGS.append(f"{name}: missing from installed release {rid}; using the wheel's copy")
        return None
    if hashlib.sha256(blob).hexdigest() != entry.get("sha256"):
        WARNINGS.append(f"{name}: changed on disk since release {rid} was installed; using the wheel's copy")
        return None
    return rid, blob
