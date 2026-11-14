#!/usr/bin/env python3
"""Cross-check our minisign implementation against the reference `minisign` binary (CI).

    python tools/minisign_interop.py [--minisign PATH]

1. sign with aiterprise_scan.minisign → `minisign -V` must accept it;
2. a key and signature made by `minisign -G` / `minisign -S` → our verify must accept it;
3. a tampered file → both must refuse it.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aiterprise_scan import minisign  # noqa: E402


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--minisign", default=shutil.which("minisign"))
    args = ap.parse_args(argv)
    if not args.minisign:
        print("minisign binary not found")
        return 2
    ms = args.minisign
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        payload = d / "manifest.json"
        payload.write_bytes(b'{"schema_version":1,"domain":"AIT"}\n')

        # 1. ours -> reference
        seed, key_id = bytes(range(32)), bytes.fromhex("0102030405060708")
        (d / "ours.pub").write_text(minisign.public_key_text(seed, key_id), encoding="utf-8")
        (d / "manifest.json.minisig").write_text(minisign.sign(seed, key_id, payload.read_bytes(), "interop"),
                                                 encoding="utf-8", newline="\n")
        r = run([ms, "-V", "-m", str(payload), "-p", str(d / "ours.pub")])
        print("minisign -V on our signature:", r.returncode, r.stdout.strip() or r.stderr.strip())
        if r.returncode != 0:
            failures.append("reference minisign refused our signature")

        # 2. reference -> ours
        r = run([ms, "-G", "-W", "-f", "-p", str(d / "ref.pub"), "-s", str(d / "ref.key")])
        if r.returncode != 0:
            print(r.stderr)
            return 2
        sig = d / "ref.minisig"
        r = run([ms, "-S", "-s", str(d / "ref.key"), "-m", str(payload), "-x", str(sig), "-t", "ref comment"])
        if r.returncode != 0:
            print(r.stderr)
            return 2
        pub = minisign.parse_public_key((d / "ref.pub").read_text(encoding="utf-8"))
        try:
            comment = minisign.verify(pub, payload.read_bytes(), sig.read_text(encoding="utf-8"))
            print("our verify on a minisign signature: OK, trusted comment:", comment)
        except minisign.SignatureError as err:
            failures.append(f"our verify refused a reference signature: {err}")

        # 3. tampered
        tampered = payload.read_bytes() + b" "
        try:
            minisign.verify(pub, tampered, sig.read_text(encoding="utf-8"))
            failures.append("our verify accepted a tampered file")
        except minisign.SignatureError:
            print("our verify refused the tampered file: OK")
        payload.write_bytes(tampered)
        r = run([ms, "-V", "-m", str(payload), "-p", str(d / "ours.pub")])
        if r.returncode == 0:
            failures.append("reference minisign accepted a tampered file")
    for f in failures:
        print("FAIL:", f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
