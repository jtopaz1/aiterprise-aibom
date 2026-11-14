#!/usr/bin/env python3
"""Build and sign an AIT definition bundle in the SecDB layout (`14a` §7.2, design doc 13 §5.4).

    python tools/build_bundle.py keygen --out keys/ --name signing
    python tools/build_bundle.py keygen --out keys/ --name root
    python tools/build_bundle.py build --out dist/bundle --channel stable \
        --seed keys/signing.seed --key-id <HEX> --root-seed keys/root.seed --root-key-id <HEX>

Output directory: `manifest.json`, `signature.minisig` (minisign, prehashed `ED`, over the exact
manifest bytes), `bundle.tar.gz` (content/<file> for every `data/ait` file), and
`signing-keys.json` + `signing-keys.json.minisig` signed by the root key. `aiterprise-scan defs
verify DIR --root-key keys/root.pub` checks it the way a client does.

Seeds are 32 random bytes in hex. Keep them offline; the root seed belongs in a key ceremony, not
on a build machine (open point O-23). SecDB's production bundles are signed by SecDB, not by this
tool — it exists for air-gapped mirrors, tests and release rehearsals.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import secrets
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aiterprise_scan import bundles, minisign  # noqa: E402

DATA_DIR = Path(__file__).resolve().parents[1] / "src" / "aiterprise_scan" / "data" / "ait"
ARCHIVE = "bundle.tar.gz"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _tar_gz(members: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(members):
            info = tarfile.TarInfo(path)
            info.size = len(members[path])
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(members[path]))
    return gzip.compress(raw.getvalue(), mtime=0)


def write_bundle(out: Path, files: dict[str, bytes], channel: str, created_at: str, seed: bytes, key_id: bytes,
                 parent: str | None = None, archive_files: dict[str, bytes] | None = None,
                 sources: list[dict] | None = None) -> str:
    """Write manifest, signature and archive; return the release id. `archive_files` overrides
    what goes into the archive (tests use it to build bundles that must be refused)."""
    out.mkdir(parents=True, exist_ok=True)
    listed = {f"content/{name}": blob for name, blob in sorted(files.items())}
    archive = _tar_gz(listed if archive_files is None else archive_files)
    manifest = {
        "schema_version": 1,
        "channel": channel,
        "domain": bundles.DOMAIN,
        "format": bundles.FORMAT,
        "created_at": created_at,
        "parent_release_id": parent,
        "row_count": len(listed),
        "archive": {"name": ARCHIVE, "sha256": _sha(archive), "bytes": len(archive)},
        "files": [{"path": p, "sha256": _sha(b), "bytes": len(b)} for p, b in listed.items()],
        "sources": sources or [{"source": "aiterprise", "licence": {"spdx": "Apache-2.0"},
                                "attribution": "AIterprise definition data"}],
        "signing_key_id": minisign.key_id_hex(key_id),
        "min_client_version": None,
    }
    manifest["release_id"] = bundles.release_id(manifest)
    body = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    (out / "manifest.json").write_bytes(body)
    stamp = int(dt.datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp())
    (out / "signature.minisig").write_text(
        minisign.sign(seed, key_id, body, f"timestamp:{stamp}\tfile:manifest.json\trelease:{manifest['release_id']}"),
        encoding="utf-8", newline="\n")
    (out / ARCHIVE).write_bytes(archive)
    return manifest["release_id"]


def key_entry(seed: bytes, key_id: bytes, not_before: str, not_after: str, status: str = "active") -> dict:
    pub = minisign.public_key_text(seed, key_id).splitlines()[1]
    return {"key_id": minisign.key_id_hex(key_id), "public_key": pub, "not_before": not_before,
            "not_after": not_after, "status": status}


def signing_keys_doc(issued_at: str, expires_at: str, keys: list[dict]) -> dict:
    return {"schema_version": 1, "issued_at": issued_at, "expires_at": expires_at, "keys": keys}


def write_signing_keys(out: Path, doc: dict, root_seed: bytes, root_key_id: bytes) -> None:
    body = json.dumps(doc, indent=2).encode("utf-8") + b"\n"
    (out / "signing-keys.json").write_bytes(body)
    (out / "signing-keys.json.minisig").write_text(
        minisign.sign(root_seed, root_key_id, body, f"file:signing-keys.json\tissued:{doc['issued_at']}"),
        encoding="utf-8", newline="\n")


def _read_seed(path: Path) -> bytes:
    seed = bytes.fromhex(path.read_text(encoding="utf-8").strip())
    if len(seed) != 32:
        raise SystemExit(f"{path}: a seed is 32 bytes of hex")
    return seed


def _iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen", help="new Ed25519 seed + minisign public key")
    kg.add_argument("--out", type=Path, required=True)
    kg.add_argument("--name", required=True)
    b = sub.add_parser("build", help="build and sign a bundle from data/ait")
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--channel", default="stable")
    b.add_argument("--seed", type=Path, required=True, help="signing key seed (hex)")
    b.add_argument("--key-id", required=True, help="signing key id (16 hex digits, as minisign prints it)")
    b.add_argument("--root-seed", type=Path, required=True)
    b.add_argument("--root-key-id", required=True)
    b.add_argument("--parent", help="parent release id")
    b.add_argument("--data", type=Path, default=DATA_DIR)
    b.add_argument("--keys-valid-days", type=int, default=60)
    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        args.out.mkdir(parents=True, exist_ok=True)
        seed, key_id = secrets.token_bytes(32), secrets.token_bytes(8)
        (args.out / f"{args.name}.seed").write_text(seed.hex() + "\n", encoding="utf-8")
        (args.out / f"{args.name}.pub").write_text(minisign.public_key_text(seed, key_id), encoding="utf-8")
        print(f"{args.name}: key id {minisign.key_id_hex(key_id)} -> {args.out / (args.name + '.pub')}")
        return 0

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    files = {p.name: p.read_bytes() for p in sorted(args.data.iterdir()) if p.is_file()}
    seed, key_id = _read_seed(args.seed), minisign.key_id_from_hex(args.key_id)
    rid = write_bundle(args.out, files, args.channel, _iso(now), seed, key_id, parent=args.parent)
    keys = signing_keys_doc(_iso(now), _iso(now + dt.timedelta(days=args.keys_valid_days)),
                            [key_entry(seed, key_id, _iso(now - dt.timedelta(days=1)),
                                       _iso(now + dt.timedelta(days=365)))])
    write_signing_keys(args.out, keys, _read_seed(args.root_seed), minisign.key_id_from_hex(args.root_key_id))
    print(f"{rid} - {len(files)} files -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
