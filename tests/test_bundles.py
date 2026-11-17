"""Signed definition bundles: verification order, refusals, install, rollback, and data precedence."""

import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import bundles, cli, data, minisign, net, secdb


def _tool(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build_bundle = _tool("build_bundle")

ROOT_SEED, ROOT_ID = bytes([1]) * 32, bytes.fromhex("0102030405060708")
SIGN_SEED, SIGN_ID = bytes([2]) * 32, bytes.fromhex("1112131415161718")
NOW = dt.datetime(2026, 11, 14, 12, 0, tzinfo=dt.timezone.utc)
TAXONOMY = json.dumps({"version": "bundle-test", "libraries": [], "python_imports": {}}).encode()


def keys_doc(issued="2026-11-01T00:00:00Z", expires="2027-01-31T00:00:00Z", status="active",
             not_before="2026-11-01T00:00:00Z", not_after="2027-03-31T23:59:59Z", seed=SIGN_SEED, key_id=SIGN_ID):
    return build_bundle.signing_keys_doc(issued, expires, [build_bundle.key_entry(seed, key_id, not_before,
                                                                                  not_after, status)])


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.n = 0

    def make(self, files=None, created_at="2026-11-10T00:00:00Z", channel="stable", keys=None,
             sign_seed=SIGN_SEED, sign_id=SIGN_ID, tamper=None, archive_files=None, parent=None):
        self.n += 1
        out = self.root / f"b{self.n}"
        build_bundle.write_bundle(out, files or {"taxonomy.json": TAXONOMY}, channel=channel, created_at=created_at,
                                  seed=sign_seed, key_id=sign_id, parent=parent, archive_files=archive_files)
        build_bundle.write_signing_keys(out, keys or keys_doc(), ROOT_SEED, ROOT_ID)
        if tamper:
            tamper(out)
        return out


ROOT_PUB = minisign.parse_public_key(minisign.public_key_text(ROOT_SEED, ROOT_ID))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, path, **kw):
        return bundles.verify_dir(path, ROOT_PUB, now=NOW, **kw)

    def refused(self, path, pattern, **kw):
        with self.assertRaisesRegex(bundles.BundleError, pattern):
            self.verify(path, **kw)

    def test_a_good_bundle_verifies(self):
        v = self.verify(self.fx.make())
        self.assertTrue(v.manifest["release_id"].startswith("rel_"))
        self.assertEqual(v.manifest["release_id"], bundles.release_id(v.manifest))
        self.assertEqual(v.files["content/taxonomy.json"], TAXONOMY)
        self.assertEqual(v.manifest["domain"], "AIT")

    def test_release_id_is_sha256_of_jcs_without_release_id(self):
        m = {"b": 1, "a": "é", "release_id": "rel_x", "n": None}
        import hashlib
        expected = "rel_" + hashlib.sha256('{"a":"é","b":1,"n":null}'.encode()).hexdigest()
        self.assertEqual(bundles.release_id(m), expected)

    def test_a_changed_manifest_fails_the_signature(self):
        def tamper(out):
            p = out / "manifest.json"
            p.write_bytes(p.read_bytes().replace(b'"stable"', b'"stablE"'))
        self.refused(self.fx.make(tamper=tamper), "signature")

    def test_manifest_signed_by_an_unlisted_key(self):
        self.refused(self.fx.make(sign_seed=bytes([9]) * 32, sign_id=bytes(8)), "not in signing-keys")

    def test_revoked_or_out_of_window_signing_key(self):
        self.refused(self.fx.make(keys=keys_doc(status="revoked")), "revoked")
        self.refused(self.fx.make(keys=keys_doc(not_before="2026-11-12T00:00:00Z")), "validity window")

    def test_signing_keys_must_chain_to_the_root(self):
        def tamper(out):
            build_bundle.write_signing_keys(out, keys_doc(), bytes([7]) * 32, ROOT_ID)
        self.refused(self.fx.make(tamper=tamper), "signing-keys")

    def test_signing_keys_expiry_and_rollback(self):
        self.refused(self.fx.make(keys=keys_doc(expires="2026-11-13T00:00:00Z")), "expired")
        self.refused(self.fx.make(), "older than", keys_issued_at="2026-11-05T00:00:00Z")

    def test_archive_hash_is_checked_before_unpacking(self):
        def tamper(out):
            arc = out / "bundle.tar.gz"
            arc.write_bytes(arc.read_bytes() + b"\0")
        self.refused(self.fx.make(tamper=tamper), "archive")

    def test_unsafe_or_unlisted_archive_members(self):
        self.refused(self.fx.make(archive_files={"content/taxonomy.json": TAXONOMY, "../evil.json": b"{}"}),
                     "unsafe path|not listed")
        self.refused(self.fx.make(archive_files={"content/taxonomy.json": b"{}"}), "does not match")
        self.refused(self.fx.make(archive_files={}), "missing")

    def test_expectations_and_downgrade(self):
        path = self.fx.make()
        self.refused(path, "domain", expect={"domain": "WEB"})
        self.refused(path, "release", expect={"release_id": "rel_" + "0" * 64})
        self.refused(path, "older than the installed", installed_created_at="2026-11-11T00:00:00Z")

    def test_stale_release_id_is_refused(self):
        def tamper(out):
            m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            m["row_count"] = 999  # edited after release_id was computed, then re-signed
            body = json.dumps(m, indent=2).encode()
            (out / "manifest.json").write_bytes(body)
            (out / "signature.minisig").write_text(minisign.sign(SIGN_SEED, SIGN_ID, body, "t"), encoding="utf-8")
        self.refused(self.fx.make(tamper=tamper), "release_id")


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.fx = Fixture(Path(self.tmp.name))
        self.env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": str(self.home)})
        self.env.start()
        os.environ.pop("AITERPRISE_DEFS", None)
        data.load.cache_clear()

    def tearDown(self):
        self.env.stop()
        data.load.cache_clear()
        self.tmp.cleanup()

    def install(self, path):
        return bundles.install(bundles.verify_dir(path, ROOT_PUB, now=NOW))

    def test_installed_bundle_takes_precedence_and_can_be_disabled(self):
        self.assertNotEqual(data.load("taxonomy.json").get("version"), "bundle-test")
        data.load.cache_clear()
        rid = self.install(self.fx.make())
        self.assertEqual(data.load("taxonomy.json")["version"], "bundle-test")
        self.assertEqual(data.source("taxonomy.json"), f"bundle {rid}")
        self.assertEqual(data.source("command-rules.json"), "wheel")  # not in the bundle
        data.load.cache_clear()
        with mock.patch.dict(os.environ, {"AITERPRISE_DEFS": "bundled"}):
            self.assertNotEqual(data.load("taxonomy.json").get("version"), "bundle-test")

    def test_tampered_installed_file_falls_back_to_the_wheel(self):
        rid = self.install(self.fx.make())
        (self.home / "defs" / rid / "content" / "taxonomy.json").write_bytes(b'{"version": "evil"}')
        self.assertNotEqual(data.load("taxonomy.json").get("version"), "evil")
        self.assertTrue(any("taxonomy.json" in w for w in bundles.WARNINGS))

    def test_rollback_restores_the_previous_release_then_the_wheel(self):
        first = self.install(self.fx.make(created_at="2026-11-10T00:00:00Z"))
        second = self.install(self.fx.make(created_at="2026-11-11T00:00:00Z", parent=first))
        self.assertEqual(bundles.state()["current"], second)
        self.assertEqual(bundles.rollback(), first)
        self.assertEqual(bundles.state()["current"], first)
        self.assertIsNone(bundles.rollback())
        self.assertIsNone(bundles.state()["current"])

    def test_a_failed_verification_keeps_the_last_good_release(self):
        good = self.install(self.fx.make())
        bad = self.fx.make(keys=keys_doc(status="revoked"))
        with self.assertRaises(bundles.BundleError):
            self.install(bad)
        self.assertEqual(bundles.state()["current"], good)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.fx = Fixture(Path(self.tmp.name))
        self.pub = Path(self.tmp.name) / "root.pub"
        self.pub.write_text(minisign.public_key_text(ROOT_SEED, ROOT_ID), encoding="utf-8")
        self.env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": str(self.home)})
        self.env.start()
        for k in ("AITERPRISE_API_KEY", "AITERPRISE_ROOT_KEY", "AITERPRISE_DEFS"):
            os.environ.pop(k, None)
        data.load.cache_clear()

    def tearDown(self):
        self.env.stop()
        data.load.cache_clear()
        self.tmp.cleanup()

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(bundles, "_now", return_value=NOW):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_verify_install_status_rollback(self):
        path = self.fx.make()
        code, out, err = self.run_cli(["defs", "verify", str(path), "--root-key", str(self.pub)])
        self.assertEqual(code, 0, err)
        self.assertIn("rel_", out)
        code, out, err = self.run_cli(["defs", "install", str(path), "--root-key", str(self.pub)])
        self.assertEqual(code, 0, err)
        code, out, _ = self.run_cli(["defs", "status"])
        self.assertIn("installed bundle: rel_", out)
        self.assertIn("taxonomy.json: present, version bundle-test (bundle rel_", out)
        self.assertRegex(out, r"known-bad-hashes\.json: present, version [0-9.]+, [0-9]+ entries \(wheel\)")
        self.assertRegex(out, r"poison-patterns\.json: present, version [0-9.]+, [0-9]+ rules \(wheel\)")
        code, out, _ = self.run_cli(["defs", "rollback"])
        self.assertEqual(code, 0)
        self.assertIn("wheel", out)

    def test_without_a_root_key_nothing_is_installed(self):
        code, _, err = self.run_cli(["defs", "install", str(self.fx.make())])
        self.assertEqual(code, 2)
        self.assertIn("root key", err)
        self.assertIsNone(bundles.state()["current"])

    def test_update_when_secdb_has_no_ait_bundle(self):
        def transport(method, url, body, headers):
            self.assertIn("/v1/releases/latest?domain=AIT&format=ait-bundle", url)
            raise net.NetError("404", 404, {"type": "https://api.aiterprise.net/problems/not_found"})
        with mock.patch.object(secdb, "DEFAULT_TRANSPORT", transport):
            code, out, _ = self.run_cli(["defs", "update"])
        self.assertEqual(code, 0)
        self.assertIn("no AIT bundle", out)


if __name__ == "__main__":
    unittest.main()
