"""`aiterprise-scan defs verify|install|update|rollback` (design doc 13 §5.4; `14a` §7.3)."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit

from . import TOOL_NAME, bundles, credentials, net, secdb


def _err(msg: str) -> int:
    print(f"{TOOL_NAME}: error: {msg}", file=sys.stderr)
    return 2


def _held() -> tuple[str | None, str | None]:
    st = bundles.state()
    cur = st.get("current")
    created = (st["releases"].get(cur) or {}).get("created_at") if cur else None
    return st.get("keys_issued_at"), created


def _verify(path: Path, root_path: Path | None, expect: dict | None = None) -> bundles.Verified:
    issued, created = _held()
    return bundles.verify_dir(path, bundles.root_key(root_path), expect=expect, keys_issued_at=issued,
                              installed_created_at=created, now=bundles._now())


def _describe(v: bundles.Verified) -> str:
    m = v.manifest
    return (f"{m['release_id']} · {m.get('channel')} · created {m.get('created_at')} · "
            f"{len(v.files)} file(s) · signed by {m.get('signing_key_id')}")


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        v = _verify(args.dir, args.root_key)
    except bundles.BundleError as err:
        return _err(f"bundle refused: {err}")
    print(f"verified: {_describe(v)}")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    try:
        v = _verify(args.dir, args.root_key)
    except bundles.BundleError as err:
        return _err(f"bundle refused, last good release kept: {err}")
    bundles.install(v)
    print(f"installed and active: {_describe(v)}")
    earlier = len(bundles.state()["history"]) - 1
    print("`defs rollback` returns to " + ("the previous release" if earlier else "the definitions shipped with "
                                           "this version"))
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    rid = bundles.rollback()
    print(f"active definitions: {'bundle ' + rid if rid else 'the wheel data shipped with this version'}")
    return 0


def _sibling(url: str, name: str) -> str:
    parts = urlsplit(url)
    path = str(PurePosixPath(parts.path).parent / name)
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def cmd_update(args: argparse.Namespace) -> int:
    client = secdb.Client(credentials.load())
    st = bundles.state()
    try:
        rel = client.releases_latest(bundles.DOMAIN, bundles.FORMAT, args.channel, st.get("current"))
    except secdb.SecDBError as err:
        if err.status == 404:
            print("SecDB has no AIT bundle published yet; the definitions shipped with this version stay in use")
            return 0
        return _err(str(err))
    if rel is None:
        print(f"up to date: {st.get('current')}")
        return 0
    rid = rel.get("release_id")
    urls = {k: rel.get(k) for k in ("manifest_url", "signature_url", "bundle_url")}
    if not rid or not all(urls.values()):
        return _err(f"release {rid} has no download URLs (it is not a downloadable bundle)")
    try:
        root = bundles.root_key(args.root_key)
    except bundles.BundleError as err:
        return _err(f"release {rid} is available, but it cannot be verified: {err}")
    arc_name = str(((rel.get("manifest") or {}).get("archive") or {}).get("name") or "")
    if not arc_name or "/" in arc_name or "\\" in arc_name or arc_name.startswith("."):
        arc_name = PurePosixPath(urlsplit(urls["bundle_url"]).path).name
    keys_url = args.signing_keys or rel.get("signing_keys_url") or _sibling(urls["manifest_url"], "signing-keys.json")
    with tempfile.TemporaryDirectory(prefix="aiterprise-defs-") as tmp:
        d = Path(tmp)
        try:
            (d / "manifest.json").write_bytes(net.download(urls["manifest_url"], 4 * 1024 * 1024))
            (d / "signature.minisig").write_bytes(net.download(urls["signature_url"], 64 * 1024))
            (d / "signing-keys.json").write_bytes(net.download(keys_url, 1024 * 1024))
            (d / "signing-keys.json.minisig").write_bytes(net.download(keys_url + ".minisig", 64 * 1024))
            (d / arc_name).write_bytes(net.download(urls["bundle_url"], bundles.MAX_ARCHIVE))
        except net.NetError as err:
            return _err(f"download failed, last good release kept: {err}")
        expect = {"release_id": rid, "channel": rel.get("channel"), "domain": bundles.DOMAIN,
                  "format": bundles.FORMAT}
        try:
            issued, created = _held()
            v = bundles.verify_dir(d, root, expect=expect, keys_issued_at=issued, installed_created_at=created,
                                   now=bundles._now())
        except bundles.BundleError as err:
            return _err(f"bundle refused, last good release kept: {err}")
        bundles.install(v)
    print(f"updated: {_describe(v)}")
    return 0


HANDLERS = {"verify": cmd_verify, "install": cmd_install, "update": cmd_update, "rollback": cmd_rollback}
