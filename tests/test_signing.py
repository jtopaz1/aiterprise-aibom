"""Pure-Python Ed25519 (RFC 8032) and the minisign signature format."""

import base64
import hashlib
import unittest

from aiterprise_scan import ed25519, minisign

# RFC 8032 §7.1, TEST 1 and TEST 2
VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
     "d25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
     "387b2eaeb4302aeeb00d291612bb0c00"),
]

SEED = bytes(range(32))
KEY_ID = bytes.fromhex("5b4a0f1e2d3b9c7a")  # little-endian of 7A9C3B2D1E0F4A5B


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for sk, pk, msg, sig in VECTORS:
            seed, msg_b = bytes.fromhex(sk), bytes.fromhex(msg)
            self.assertEqual(ed25519.public_key(seed).hex(), pk)
            self.assertEqual(ed25519.sign(seed, msg_b).hex(), sig)
            self.assertTrue(ed25519.verify(bytes.fromhex(pk), msg_b, bytes.fromhex(sig)))

    def test_rejects_a_changed_message_or_signature(self):
        pk = ed25519.public_key(SEED)
        sig = ed25519.sign(SEED, b"manifest")
        self.assertFalse(ed25519.verify(pk, b"manifesT", sig))
        bad = bytearray(sig)
        bad[5] ^= 1
        self.assertFalse(ed25519.verify(pk, b"manifest", bytes(bad)))
        self.assertFalse(ed25519.verify(pk, b"manifest", sig[:63]))

    def test_rejects_a_non_canonical_s(self):
        pk = ed25519.public_key(SEED)
        sig = ed25519.sign(SEED, b"m")
        s = int.from_bytes(sig[32:], "little") + ed25519.L  # same point, malleated scalar
        self.assertFalse(ed25519.verify(pk, b"m", sig[:32] + s.to_bytes(32, "little")))


class MinisignTests(unittest.TestCase):
    def test_key_id_prints_as_minisign_does(self):
        self.assertEqual(minisign.key_id_hex(KEY_ID), "7A9C3B2D1E0F4A5B")
        self.assertEqual(minisign.key_id_from_hex("7A9C3B2D1E0F4A5B"), KEY_ID)

    def test_public_key_text_round_trips(self):
        text = minisign.public_key_text(SEED, KEY_ID)
        self.assertTrue(text.startswith("untrusted comment: minisign public key 7A9C3B2D1E0F4A5B\n"))
        pub = minisign.parse_public_key(text)
        self.assertEqual(pub.key_id, KEY_ID)
        self.assertEqual(pub.key, ed25519.public_key(SEED))
        raw = base64.b64decode(text.splitlines()[1])
        self.assertEqual(raw[:2], b"Ed")
        self.assertEqual(minisign.parse_public_key(text.splitlines()[1]), pub)  # bare base64 line too

    def test_prehashed_signature_verifies_and_returns_the_trusted_comment(self):
        pub = minisign.parse_public_key(minisign.public_key_text(SEED, KEY_ID))
        sig = minisign.sign(SEED, KEY_ID, b"{}", "timestamp:1 file:manifest.json")
        lines = sig.splitlines()
        self.assertEqual(len(lines), 4)
        self.assertEqual(base64.b64decode(lines[1])[:2], b"ED")
        self.assertEqual(minisign.verify(pub, b"{}", sig), "timestamp:1 file:manifest.json")

    def test_legacy_signature_over_the_raw_message(self):
        pub = minisign.parse_public_key(minisign.public_key_text(SEED, KEY_ID))
        sig = minisign.sign(SEED, KEY_ID, b"payload", "c", prehash=False)
        self.assertEqual(base64.b64decode(sig.splitlines()[1])[:2], b"Ed")
        self.assertEqual(minisign.verify(pub, b"payload", sig), "c")

    def test_prehash_is_blake2b_512(self):
        sig = minisign.parse_signature(minisign.sign(SEED, KEY_ID, b"x", "c"))
        digest = hashlib.blake2b(b"x", digest_size=64).digest()
        self.assertTrue(ed25519.verify(ed25519.public_key(SEED), digest, sig.signature))

    def test_refusals(self):
        pub = minisign.parse_public_key(minisign.public_key_text(SEED, KEY_ID))
        sig = minisign.sign(SEED, KEY_ID, b"manifest", "trusted")
        with self.assertRaisesRegex(minisign.SignatureError, "does not match"):
            minisign.verify(pub, b"manifesT", sig)
        forged = sig.replace("trusted comment: trusted", "trusted comment: forged")
        with self.assertRaisesRegex(minisign.SignatureError, "trusted comment"):
            minisign.verify(pub, b"manifest", forged)
        other = minisign.sign(SEED, bytes(8), b"manifest", "trusted")
        with self.assertRaisesRegex(minisign.SignatureError, "key"):
            minisign.verify(pub, b"manifest", other)
        with self.assertRaises(minisign.SignatureError):
            minisign.verify(pub, b"manifest", "not a signature")


if __name__ == "__main__":
    unittest.main()
